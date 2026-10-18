from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from functools import cached_property
from typing import TYPE_CHECKING, Any, Final, cast
from uuid import uuid4

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_injected import inject
from pydantic import AnyHttpUrl, BaseModel

from fastapi_authn._lifespan import lifespan_of
from fastapi_authn.exceptions import UserError
from fastapi_authn.oauth.errors import AuthorizeError, TokenError
from fastapi_authn.oauth.models import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    ClientInformation,
    DeviceAuthorization,
    OAuthToken,
    RefreshToken,
    construct_redirect_uri,
)
from fastapi_authn.oauth.resource import as_http_url
from fastapi_authn.oauth.types import AuthenticationResult, Record

from .hooks import ProviderHooks
from .protocol import DeviceAuthorizationOptions
from .storage import (
    Denied,
    DeviceGrant,
    Grant,
    Identity,
    Namespace,
    OAuthStorage,
    StoredCode,
    StoredRefreshToken,
    Transaction,
)
from .upstream import Upstream

if TYPE_CHECKING:
    from fastapi_authn.oauth.providers.identity import Authenticate

    from .signer import AccessTokenSigner

__all__ = [
    "StoredProvider",
    "TransactionDescription",
]

logger = logging.getLogger(__name__)

NO_STORE: Final = {"Cache-Control": "no-store"}
TOKEN_BYTES: Final = 32
# RFC 8628 §6.1: a user types this, so no vowels or look-alikes.
USER_CODE_ALPHABET: Final = "BCDFGHJKLMNPQRSTVWXZ"
USER_CODE_LENGTH: Final = 8


class TransactionDescription(BaseModel):
    """What a login page may show about the client asking for authorization."""

    client_id: str
    client_name: str | None = None
    client_uri: AnyHttpUrl | None = None
    logo_uri: AnyHttpUrl | None = None
    scopes: list[str]


def oauth_error(error: str, description: str, *, status_code: int = status.HTTP_400_BAD_REQUEST) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=NO_STORE,
    )


def new_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def digest(secret: str) -> str:
    # Codes, tokens and states are stored under a hash, so a copy of the storage holds no usable credential.
    return hashlib.sha256(secret.encode()).hexdigest()


@dataclass(kw_only=True)
class StoredProvider:
    """An `AuthorizationServerProvider` over any `OAuthStorage`, authenticating users through an `Upstream`.

    Issues opaque access and refresh tokens of its own, carrying the identity's claims; with a `signer`, the
    access tokens are JWTs (RFC 9068) a resource server elsewhere can verify on its own.
    """

    storage: OAuthStorage
    # Where this server is reachable; the upstream sends the user back to `callback_path` under it.
    issuer_url: AnyHttpUrl | str
    # Either an upstream, or `login_url` with an `@provider.authenticate` function for your own sign-in page.
    upstream: Upstream | None = None
    login_url: str | None = None
    callback_path: str = "/oauth/callback"
    transaction_path: str = "/oauth/transaction"
    transaction_ttl: timedelta = timedelta(minutes=10)
    code_ttl: timedelta = timedelta(minutes=5)
    access_token_ttl: timedelta = timedelta(hours=1)
    refresh_token_ttl: timedelta | None = timedelta(days=30)
    # `@provider.on.identity` and `@provider.on.access_token`.
    on: ProviderHooks = field(default_factory=ProviderHooks)
    signer: AccessTokenSigner | None = None

    @cached_property
    def issuer(self) -> AnyHttpUrl:
        return as_http_url(self.issuer_url)

    @cached_property
    def callback_url(self) -> str:
        return str(self.issuer).rstrip("/") + self.callback_path

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        """Runs the storage's and the upstream's lifespans, when they declare one."""
        async with AsyncExitStack() as stack:
            for dependency in (self.storage, self.upstream):
                if (lifespan := lifespan_of(dependency)) is not None:
                    await stack.enter_async_context(lifespan(app))

            yield

    @property
    def authentication(self) -> Upstream:
        if self.upstream is None:
            raise UserError("Give the provider an upstream, or a login_url and an @provider.authenticate function")

        return self.upstream

    def authenticate[F: Authenticate](self, func: F, /) -> F:
        """Your own sign-in page as the upstream: `func` turns what the page posts back into an identity."""
        from fastapi_authn.oauth.providers.identity import IdentityUpstream

        if self.login_url is None:
            raise UserError("@provider.authenticate needs the provider's login_url")

        if self.upstream is not None:
            raise UserError("The provider already has an upstream")

        authenticate = cast("Authenticate", inject(new_ctx=True)(func))
        self.upstream = IdentityUpstream(login_url=self.login_url, authenticate=authenticate)
        return func

    # Clients

    async def get_client(self, client_id: str) -> ClientInformation | None:
        match await self.storage.get(Namespace.CLIENTS, client_id):
            case None:
                return None
            case record:
                return ClientInformation.model_validate(record)

    async def register_client(self, client: ClientInformation) -> None:
        ttl = None
        if client.client_secret_expires_at:
            ttl = timedelta(seconds=max(client.client_secret_expires_at - time.time(), 0))

        await self.storage.set(Namespace.CLIENTS, client.client_id, dump(client), ttl=ttl)

    async def delete_client(self, client_id: str) -> None:
        await self.storage.delete(Namespace.CLIENTS, client_id)

    # Authorization

    async def authorize(self, client: ClientInformation, params: AuthorizationParams) -> str:
        transaction = Transaction(
            id=new_token(),
            client_id=client.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=params.scopes or [],
            state=params.state,
            resource=params.resource,
        )

        try:
            url = await self.authentication.start(transaction, callback_url=self.callback_url)
        except Exception as e:
            logger.exception("Upstream refused to start an authorization")
            raise AuthorizeError("temporarily_unavailable", "Could not start authentication") from e

        await self.storage.set(
            Namespace.TRANSACTIONS, digest(transaction.id), dump(transaction), ttl=self.transaction_ttl
        )
        return url

    async def transaction(self, state: str) -> Transaction | None:
        match await self.storage.get(Namespace.TRANSACTIONS, digest(state)):
            case None:
                return None
            case record:
                return Transaction.model_validate(record)

    async def complete(self, state: str, result: AuthenticationResult) -> str | None:
        """Finish a transaction with what the user did; the URL to send them back to the client, if any."""
        if (record := await self.storage.pop(Namespace.TRANSACTIONS, digest(state))) is None:
            return None

        transaction = Transaction.model_validate(record)
        redirect_uri = str(transaction.redirect_uri)
        # RFC 9207: the response names its issuer, so a client talking to several servers can tell them apart.
        issuer = str(self.issuer)

        if isinstance(result, Identity) and self.on.identity_hooks:
            client = await self.get_client(transaction.client_id)
            if client is None:
                result = Denied(error="invalid_client", description="The client is no longer registered")
            else:
                result = await self.on.run_identity(result, client, transaction)

        match result:
            case Denied(error=error, description=description):
                return construct_redirect_uri(
                    redirect_uri, error=error, error_description=description, state=transaction.state, iss=issuer
                )
            case Identity() as identity:
                code = AuthorizationCode(
                    code=new_token(),
                    scopes=identity.scopes if identity.scopes is not None else transaction.scopes,
                    expires_at=time.time() + self.code_ttl.total_seconds(),
                    client_id=transaction.client_id,
                    code_challenge=transaction.code_challenge,
                    redirect_uri=transaction.redirect_uri,
                    redirect_uri_provided_explicitly=transaction.redirect_uri_provided_explicitly,
                    resource=transaction.resource,
                    subject=identity.subject,
                )
                stored = StoredCode(code=code, identity=identity, grant_id=new_token())
                await self.storage.set(Namespace.CODES, digest(code.code), dump(stored), ttl=self.code_ttl)

                return construct_redirect_uri(redirect_uri, code=code.code, state=transaction.state, iss=issuer)

    # Codes

    async def load_authorization_code(self, client: ClientInformation, code: str) -> AuthorizationCode | None:
        key = digest(code)

        match await self.storage.get(Namespace.CODES, key):
            case None:
                # A code presented again after its exchange may have leaked: what it produced is revoked
                # (RFC 6749 §4.1.2).
                if (used := await self.storage.pop(Namespace.USED_CODES, key)) is not None:
                    await self.revoke_grant(used["grant_id"])

                return None
            case record:
                stored = StoredCode.model_validate(record)
                return stored.code if stored.code.client_id == client.client_id else None

    async def exchange_authorization_code(self, client: ClientInformation, code: AuthorizationCode) -> OAuthToken:
        key = digest(code.code)

        # Popped, so one exchange wins; the tombstone is what a replay finds in `load_authorization_code`.
        if (record := await self.storage.pop(Namespace.CODES, key)) is None:
            raise TokenError("invalid_grant", "Authorization code already used")

        stored = StoredCode.model_validate(record)
        grant_id = stored.grant_id or new_token()
        await self.storage.set(Namespace.USED_CODES, key, {"grant_id": grant_id}, ttl=self.grant_ttl)

        return await self.issue(
            client, scopes=code.scopes, resource=code.resource, identity=stored.identity, grant_id=grant_id
        )

    # Tokens

    @property
    def grant_ttl(self) -> timedelta:
        return self.refresh_token_ttl if self.refresh_token_ttl is not None else self.access_token_ttl

    def access_token_string(self, claims: dict[str, Any]) -> str:
        if self.signer is None:
            return new_token()

        return self.signer.sign(claims)

    async def issue(
        self,
        client: ClientInformation,
        *,
        scopes: list[str],
        resource: str | None,
        identity: Identity,
        grant_id: str,
    ) -> OAuthToken:
        now = int(time.time())
        expires_at = now + int(self.access_token_ttl.total_seconds())
        # RFC 9068 §2.2; the identity's own claims never override the registered ones.
        claims = {
            **identity.claims,
            "iss": str(self.issuer),
            "sub": identity.subject,
            "aud": resource or client.client_id,
            "client_id": client.client_id,
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid4()),
            "scope": " ".join(scopes),
        }

        access_token = AccessToken(
            token=self.access_token_string(claims),
            client_id=client.client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=resource,
            subject=identity.subject,
            claims=claims,
        )
        await self.storage.set(
            Namespace.ACCESS_TOKENS, digest(access_token.token), dump(access_token), ttl=self.access_token_ttl
        )
        grant = Grant(access_tokens=[digest(access_token.token)])

        refresh_token = None
        # Only a client registered for the grant gets one (RFC 7591 §2).
        if self.refresh_token_ttl is not None and "refresh_token" in client.grant_types:
            refresh_token = RefreshToken(
                token=new_token(),
                client_id=client.client_id,
                scopes=scopes,
                expires_at=now + int(self.refresh_token_ttl.total_seconds()),
                resource=access_token.resource,
                subject=identity.subject,
                grant_id=grant_id,
            )
            stored = StoredRefreshToken(token=refresh_token, identity=identity, grant_id=grant_id)
            await self.storage.set(
                Namespace.REFRESH_TOKENS, digest(refresh_token.token), dump(stored), ttl=self.refresh_token_ttl
            )
            grant.refresh_tokens.append(digest(refresh_token.token))

        await self.remember(grant_id, grant)

        return OAuthToken(
            access_token=access_token.token,
            expires_in=int(self.access_token_ttl.total_seconds()),
            scope=" ".join(scopes) or None,
            refresh_token=refresh_token.token if refresh_token is not None else None,
        )

    async def load_refresh_token(self, client: ClientInformation, token: str) -> RefreshToken | None:
        match await self.storage.get(Namespace.REFRESH_TOKENS, digest(token)):
            case None:
                return None
            case record:
                stored = StoredRefreshToken.model_validate(record)
                return stored.token if stored.token.client_id == client.client_id else None

    async def exchange_refresh_token(
        self, client: ClientInformation, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        # Rotated: the old refresh token is gone once the new pair is issued.
        if (record := await self.storage.pop(Namespace.REFRESH_TOKENS, digest(refresh_token.token))) is None:
            raise TokenError("invalid_grant", "Refresh token already used")

        stored = StoredRefreshToken.model_validate(record)

        return await self.issue(
            client,
            scopes=scopes or refresh_token.scopes,
            resource=refresh_token.resource,
            identity=stored.identity,
            grant_id=stored.grant_id or new_token(),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        match await self.storage.get(Namespace.ACCESS_TOKENS, digest(token)):
            case None:
                return None
            case record:
                return await self.on.run_access_token(AccessToken.model_validate(record))

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        match token:
            case AccessToken():
                await self.storage.delete(Namespace.ACCESS_TOKENS, digest(token.token))
            case RefreshToken(grant_id=str() as grant_id):
                # RFC 7009 §2.1: the access tokens of the same grant go with it.
                await self.revoke_grant(grant_id)
            case RefreshToken():
                await self.storage.delete(Namespace.REFRESH_TOKENS, digest(token.token))

    # Grants

    async def remember(self, grant_id: str, issued: Grant) -> None:
        # shortcut: read-modify-write, so two exchanges of one grant at the same instant may lose a digest;
        # upgrade to a storage-level append when that matters.
        grant = Grant.model_validate(await self.storage.get(Namespace.GRANTS, grant_id) or {})
        grant.access_tokens += issued.access_tokens
        grant.refresh_tokens += issued.refresh_tokens
        await self.storage.set(Namespace.GRANTS, grant_id, dump(grant), ttl=self.grant_ttl)

    async def revoke_grant(self, grant_id: str) -> None:
        """Forgets every token issued for one authorization."""
        grant = Grant.model_validate(await self.storage.pop(Namespace.GRANTS, grant_id) or {})

        for key in grant.access_tokens:
            await self.storage.delete(Namespace.ACCESS_TOKENS, key)

        for key in grant.refresh_tokens:
            await self.storage.delete(Namespace.REFRESH_TOKENS, key)

    # Device authorization (RFC 8628)

    async def start_device_authorization(
        self, client: ClientInformation, scopes: list[str], resource: str | None, options: DeviceAuthorizationOptions
    ) -> DeviceAuthorization:
        device_code = new_token()
        user_code = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))
        ttl = timedelta(seconds=options.code_ttl_seconds)
        grant = DeviceGrant(
            client_id=client.client_id,
            user_code=user_code,
            scopes=scopes,
            resource=resource,
            expires_at=int(time.time() + options.code_ttl_seconds),
            interval=options.interval_seconds,
        )

        await self.storage.set(Namespace.DEVICE_CODES, digest(device_code), dump(grant), ttl=ttl)
        await self.storage.set(Namespace.USER_CODES, user_code, {"device": digest(device_code)}, ttl=ttl)

        return DeviceAuthorization(
            device_code=device_code,
            user_code=user_code,
            verification_uri=options.verification_uri,
            verification_uri_complete=construct_redirect_uri(options.verification_uri, user_code=user_code),
            expires_in=options.code_ttl_seconds,
            interval=options.interval_seconds,
        )

    async def device_grant(self, user_code: str) -> tuple[str, DeviceGrant] | None:
        """A pending device authorization by the code the user typed, with its storage key."""
        match await self.storage.get(Namespace.USER_CODES, user_code.upper().replace("-", "")):
            case {"device": str() as key}:
                record = await self.storage.get(Namespace.DEVICE_CODES, key)
                return (key, DeviceGrant.model_validate(record)) if record is not None else None
            case _:
                return None

    async def describe_device(self, user_code: str) -> TransactionDescription | None:
        """The client behind a user code, for the verification page to show."""
        found = await self.device_grant(user_code)
        client = await self.get_client(found[1].client_id) if found is not None else None

        if found is None or client is None:
            return None

        return TransactionDescription(
            client_id=client.client_id,
            client_name=client.client_name,
            client_uri=client.client_uri,
            logo_uri=client.logo_uri,
            scopes=found[1].scopes,
        )

    async def approve_device(self, user_code: str, identity: Identity) -> bool:
        """Lets the device in as `identity`; `False` when the code is unknown or expired.

        The verification page authenticated the user itself, so the identity hooks do not run here.
        """
        return await self.decide_device(user_code, "approved", identity)

    async def deny_device(self, user_code: str) -> bool:
        return await self.decide_device(user_code, "denied", None)

    async def decide_device(self, user_code: str, status: str, identity: Identity | None) -> bool:
        if (found := await self.device_grant(user_code)) is None:
            return False

        key, grant = found
        grant = grant.model_copy(update={"status": status, "identity": identity})
        await self.storage.set(Namespace.DEVICE_CODES, key, dump(grant), ttl=self.remaining(grant))
        await self.storage.delete(Namespace.USER_CODES, grant.user_code)
        return True

    @staticmethod
    def remaining(grant: DeviceGrant) -> timedelta:
        return timedelta(seconds=max(grant.expires_at - time.time(), 0))

    async def exchange_device_code(self, client: ClientInformation, device_code: str) -> OAuthToken:
        key = digest(device_code)
        record = await self.storage.get(Namespace.DEVICE_CODES, key)
        grant = DeviceGrant.model_validate(record) if record is not None else None

        if grant is None or grant.client_id != client.client_id:
            raise TokenError("invalid_grant", "Device code does not exist")

        if grant.expires_at < time.time():
            raise TokenError("expired_token", "The user did not authorize in time")

        if grant.status == "pending":
            now = time.time()
            too_fast = now - grant.last_polled < grant.interval
            grant = grant.model_copy(update={"last_polled": now})
            await self.storage.set(Namespace.DEVICE_CODES, key, dump(grant), ttl=self.remaining(grant))

            if too_fast:
                raise TokenError("slow_down", f"Poll at most every {grant.interval} seconds")

            raise TokenError("authorization_pending", "The user has not authorized yet")

        await self.storage.delete(Namespace.DEVICE_CODES, key)

        if grant.status == "denied" or grant.identity is None:
            raise TokenError("access_denied", "The user denied the request")

        return await self.issue(
            client, scopes=grant.scopes, resource=grant.resource, identity=grant.identity, grant_id=new_token()
        )

    # The upstream's way back in

    @property
    def router(self) -> APIRouter:
        router = APIRouter(tags=["oauth"])

        router.add_api_route(
            self.callback_path,
            self.handle_callback,
            methods=list(self.authentication.callback_methods),
            name="oauth_callback",
            summary="Completes the user's authentication and sends them back to the client",
        )
        router.add_api_route(
            self.transaction_path,
            self.describe_transaction,
            methods=["GET"],
            name="oauth_transaction",
            summary="The client asking for authorization, for a login page to show",
        )

        return router

    async def handle_callback(self, request: Request) -> Response:
        upstream = self.authentication
        state = await upstream.state_of(request)
        transaction = await self.transaction(state) if state is not None else None

        if state is None or transaction is None:
            return oauth_error("invalid_request", "Unknown or expired authorization request")

        try:
            result = await upstream.complete(request, transaction, callback_url=self.callback_url)
        except Exception:
            logger.exception("Upstream failed to complete an authorization")
            result = Denied(error="server_error", description="Authentication failed")

        if (location := await self.complete(state, result)) is None:
            return oauth_error("invalid_request", "Unknown or expired authorization request")

        if upstream.callback_mode == "json":
            return JSONResponse({"redirect_url": location}, headers=NO_STORE)

        return RedirectResponse(location, status_code=status.HTTP_302_FOUND, headers=NO_STORE)

    async def describe_transaction(self, state: str) -> Response:
        transaction = await self.transaction(state)
        client = await self.get_client(transaction.client_id) if transaction is not None else None

        if transaction is None or client is None:
            return oauth_error(
                "invalid_request", "Unknown or expired authorization request", status_code=status.HTTP_404_NOT_FOUND
            )

        description = TransactionDescription(
            client_id=client.client_id,
            client_name=client.client_name,
            client_uri=client.client_uri,
            logo_uri=client.logo_uri,
            scopes=transaction.scopes,
        )

        return Response(description.model_dump_json(), headers=NO_STORE, media_type="application/json")


def dump(model: Any) -> Record:
    return model.model_dump(mode="json", exclude_none=True)
