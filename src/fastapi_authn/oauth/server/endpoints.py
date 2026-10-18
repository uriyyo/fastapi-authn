from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal
from urllib.parse import parse_qsl, unquote
from uuid import uuid4

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import AnyUrl, BaseModel, Field, TypeAdapter, ValidationError, model_validator
from starlette.datastructures import FormData, QueryParams, UploadFile

from fastapi_authn.exceptions import MissingExtra
from fastapi_authn.oauth.errors import AuthorizeError, OAuthError, RegistrationError, TokenError
from fastapi_authn.oauth.models import (
    DEFAULT_GRANT_TYPES,
    DEVICE_CODE_GRANT,
    AccessToken,
    AuthorizationParams,
    ClientInformation,
    ClientMetadata,
    RefreshToken,
    construct_redirect_uri,
)

from .protocol import (
    AuthorizationServerProvider,
    ClientRegistrationOptions,
    DeviceAuthorizationOptions,
    IntrospectionOptions,
)
from .provider import digest, new_token

__all__ = [
    "SUPPORTED_GRANT_TYPES",
    "AuthorizationEndpoint",
    "ClientAuthenticator",
    "ClientConfigurationEndpoint",
    "DeviceAuthorizationEndpoint",
    "IntrospectionEndpoint",
    "RegistrationEndpoint",
    "RevocationEndpoint",
    "TokenEndpoint",
    "metadata_response",
    "oauth_error_response",
]

SUPPORTED_GRANT_TYPES: Final = ("authorization_code", "refresh_token", DEVICE_CODE_GRANT)

logger = logging.getLogger(__name__)

NO_STORE: Final = {"Cache-Control": "no-store", "Pragma": "no-cache"}
ANY_URL: TypeAdapter[AnyUrl] = TypeAdapter(AnyUrl)
CLIENT_SECRET_BYTES: Final = 32


def oauth_error_response(error: OAuthError) -> JSONResponse:
    return JSONResponse(error.params, status_code=error.status_code, headers=NO_STORE)


def model_response(model: BaseModel, *, status_code: int = status.HTTP_200_OK, headers: dict[str, str]) -> Response:
    return Response(
        model.model_dump_json(exclude_none=True),
        status_code=status_code,
        headers=headers,
        media_type="application/json",
    )


def metadata_response(metadata: BaseModel) -> Response:
    return model_response(metadata, headers={"Cache-Control": "public, max-age=3600"})


def describe(error: ValidationError) -> str:
    return "; ".join(f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}" for e in error.errors())


async def form_data(request: Request) -> FormData:
    # OAuth endpoints take `application/x-www-form-urlencoded` only (RFC 6749 §4.1.3), parsed here without a
    # multipart library; anything else reads as an empty form and fails validation.
    content_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()

    if content_type != "application/x-www-form-urlencoded":
        return FormData()

    pairs: list[tuple[str, str | UploadFile]] = [*parse_qsl((await request.body()).decode(), keep_blank_values=True)]
    return FormData(pairs)


def unique(params: FormData | QueryParams) -> dict[str, str]:
    """The parameters as a mapping; one sent twice is refused (RFC 6749 §3.1, §3.2), never silently last-wins."""
    values: dict[str, str] = {}

    for key, value in params.multi_items():
        if key in values:
            raise OAuthError("invalid_request", f"Parameter '{key}' is repeated")

        values[key] = value if isinstance(value, str) else ""

    return values


def form_value(params: FormData | QueryParams | None, key: str) -> str | None:
    match params.get(key) if params is not None else None:
        case str() as value:
            return value
        case _:
            return None


# Client authentication (RFC 6749 §2.3)


@dataclass
class ClientAuthenticator:
    """Identifies the client behind a token or revocation request, by the method it registered with."""

    provider: AuthorizationServerProvider

    async def authenticate(self, request: Request, form: FormData) -> ClientInformation:
        basic = self.basic_credentials(request)
        # A confidential client authenticating with Basic need not repeat `client_id` in the body (RFC 6749 §2.3.1).
        client_id = form_value(form, "client_id") or (basic[0] if basic is not None else None)

        if not client_id:
            raise self.rejected("Missing client_id")

        client = await self.provider.get_client(client_id)

        if client is None:
            raise self.rejected("Invalid client_id")

        secret = self.presented_secret(form, basic, client)

        if client.client_secret is not None:
            self.check_secret(client, secret)
        elif client.token_endpoint_auth_method not in ("none", None):
            raise self.rejected("Client is registered for secret-based authentication but has no stored secret")

        return client

    def presented_secret(self, form: FormData, basic: tuple[str, str] | None, client: ClientInformation) -> str | None:
        match client.token_endpoint_auth_method:
            case "client_secret_basic":
                if basic is None:
                    raise self.rejected("Missing or invalid Basic authentication in Authorization header")

                if basic[0] != client.client_id:
                    raise self.rejected("Client ID mismatch in Basic auth")

                return basic[1]
            case "client_secret_post":
                return form_value(form, "client_secret")
            case "none" | None:
                return None
            case method:
                raise self.rejected(f"Unsupported auth method: {method}")

    def check_secret(self, client: ClientInformation, secret: str | None) -> None:
        if not secret:
            raise self.rejected("Client secret is required")

        # Stored hashed by `StoredProvider`; a seeded client may still hold it in the clear.
        stored = (client.client_secret or "").encode()

        if not (hmac.compare_digest(stored, digest(secret).encode()) or hmac.compare_digest(stored, secret.encode())):
            raise self.rejected("Invalid client_secret")

        if client.client_secret_expires_at and client.client_secret_expires_at < int(time.time()):
            raise self.rejected("Client secret has expired")

    @staticmethod
    def rejected(description: str) -> TokenError:
        return TokenError("invalid_client", description, status_code=status.HTTP_401_UNAUTHORIZED)

    @classmethod
    def basic_credentials(cls, request: Request) -> tuple[str, str] | None:
        """The `(client_id, secret)` of a Basic `Authorization` header; `None` without one."""
        header = request.headers.get("Authorization", "")

        if not header.startswith("Basic "):
            return None

        try:
            decoded = base64.b64decode(header.removeprefix("Basic ")).decode()
            client_id, _, secret = decoded.partition(":")
        except (UnicodeDecodeError, binascii.Error, ValueError) as e:
            raise cls.rejected("Invalid Basic authentication header") from e

        return unquote(client_id), unquote(secret)


# Authorization endpoint (RFC 6749 §4.1.1)


# RFC 7636 §4.1 and §4.2: unreserved characters, 43 to 128 of them, for the verifier and its S256 challenge.
type PKCEValue = Annotated[str, Field(pattern=r"^[A-Za-z0-9\-._~]{43,128}$")]


class AuthorizationRequest(BaseModel):
    client_id: str
    redirect_uri: AnyUrl | None = None
    response_type: Literal["code"]
    code_challenge: PKCEValue
    code_challenge_method: Literal["S256"] = "S256"
    state: str | None = None
    scope: str | None = None
    resource: str | None = None


@dataclass
class AuthorizationEndpoint:
    provider: AuthorizationServerProvider
    # Named in every response sent to the redirect URI, errors included (RFC 9207), when given.
    issuer: str | None = None

    async def handle(self, request: Request) -> Response:
        params = request.query_params if request.method == "GET" else await form_data(request)
        state = form_value(params, "state")

        try:
            authorization = AuthorizationRequest.model_validate(unique(params))
        except (OAuthError, ValidationError) as e:
            return await self.error(self.malformed(e), params, state)

        client = await self.provider.get_client(authorization.client_id)

        if client is None:
            return oauth_error_response(
                AuthorizeError("invalid_request", f"Client ID '{authorization.client_id}' not found")
            )

        try:
            redirect_uri = client.validate_redirect_uri(authorization.redirect_uri)
        except AuthorizeError as e:
            # Never redirect to a URI the client did not register.
            return oauth_error_response(e)

        try:
            scopes = client.validate_scope(authorization.scope)
            location = await self.provider.authorize(
                client,
                AuthorizationParams(
                    state=authorization.state,
                    scopes=scopes,
                    code_challenge=authorization.code_challenge,
                    redirect_uri=redirect_uri,
                    redirect_uri_provided_explicitly=authorization.redirect_uri is not None,
                    resource=authorization.resource,
                ),
            )
        except AuthorizeError as e:
            return self.redirect_error(str(redirect_uri), e, authorization.state)
        except Exception:
            logger.exception("Unexpected error while authorizing")
            error = AuthorizeError("server_error", "An unexpected error occurred")
            return self.redirect_error(str(redirect_uri), error, authorization.state)

        return self.redirect(location)

    @staticmethod
    def malformed(e: OAuthError | ValidationError) -> AuthorizeError:
        if isinstance(e, OAuthError):
            return AuthorizeError("invalid_request", e.description)

        if any(err["loc"] == ("response_type",) for err in e.errors()):
            return AuthorizeError("unsupported_response_type", describe(e))

        return AuthorizeError("invalid_request", describe(e))

    def redirect_error(self, redirect_uri: str, error: AuthorizeError, state: str | None) -> Response:
        return self.redirect(construct_redirect_uri(redirect_uri, **error.params, state=state, iss=self.issuer))

    async def error(self, error: AuthorizeError, params: FormData | QueryParams, state: str | None) -> Response:
        # A request that failed validation is still answered at the client's redirect URI when it can be told.
        client_id = form_value(params, "client_id")
        client = await self.provider.get_client(client_id) if client_id else None

        if client is not None:
            try:
                raw = form_value(params, "redirect_uri")
                redirect_uri = client.validate_redirect_uri(ANY_URL.validate_python(raw) if raw else None)
            except (ValidationError, AuthorizeError):
                pass
            else:
                return self.redirect_error(str(redirect_uri), error, state)

        return oauth_error_response(error)

    @staticmethod
    def redirect(location: str) -> Response:
        return RedirectResponse(location, status_code=status.HTTP_302_FOUND, headers=NO_STORE)


# Token endpoint (RFC 6749 §4.1.3, §6)


class AuthorizationCodeRequest(BaseModel):
    grant_type: Literal["authorization_code"]
    code: str
    redirect_uri: AnyUrl | None = None
    # The client is identified by `ClientAuthenticator`; here only for public clients.
    client_id: str | None = None
    code_verifier: PKCEValue
    resource: str | None = None


class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]
    refresh_token: str
    scope: str | None = None
    client_id: str | None = None
    resource: str | None = None


class DeviceCodeRequest(BaseModel):
    grant_type: Literal["urn:ietf:params:oauth:grant-type:device_code"]
    device_code: str
    client_id: str | None = None


TokenRequest = Annotated[
    AuthorizationCodeRequest | RefreshTokenRequest | DeviceCodeRequest, Field(discriminator="grant_type")
]
TOKEN_REQUEST: Final = TypeAdapter[Any](TokenRequest)


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


@dataclass
class TokenEndpoint:
    provider: AuthorizationServerProvider
    clients: ClientAuthenticator

    async def handle(self, request: Request) -> Response:
        form = await form_data(request)

        try:
            client = await self.clients.authenticate(request, form)
            token_request = self.parse(form)

            if token_request.grant_type not in client.grant_types:
                raise TokenError(
                    "unauthorized_client", f"Client was not registered for the {token_request.grant_type} grant"
                )

            match token_request:
                case AuthorizationCodeRequest():
                    tokens = await self.authorization_code(client, token_request)
                case RefreshTokenRequest():
                    tokens = await self.refresh_token(client, token_request)
                case DeviceCodeRequest():
                    tokens = await self.provider.exchange_device_code(client, token_request.device_code)
        except OAuthError as e:
            return oauth_error_response(e)

        return model_response(tokens, headers=NO_STORE)

    @staticmethod
    def parse(form: FormData) -> AuthorizationCodeRequest | RefreshTokenRequest | DeviceCodeRequest:
        try:
            return TOKEN_REQUEST.validate_python(unique(form))
        except ValidationError as e:
            if form_value(form, "grant_type") not in SUPPORTED_GRANT_TYPES:
                raise TokenError(
                    "unsupported_grant_type", f"Supported grant types: {', '.join(SUPPORTED_GRANT_TYPES)}"
                ) from e

            raise TokenError("invalid_request", describe(e)) from e

    async def authorization_code(self, client: ClientInformation, request: AuthorizationCodeRequest) -> Any:
        code = await self.provider.load_authorization_code(client, request.code)

        # A code of another client is treated as unknown.
        if code is None or code.client_id != client.client_id:
            raise TokenError("invalid_grant", "Authorization code does not exist")

        if code.expires_at < time.time():
            raise TokenError("invalid_grant", "Authorization code has expired")

        expected = str(code.redirect_uri) if code.redirect_uri_provided_explicitly else None
        sent = str(request.redirect_uri) if request.redirect_uri is not None else None

        if expected != sent:
            raise TokenError("invalid_request", "redirect_uri did not match the one used when creating the code")

        if not hmac.compare_digest(pkce_challenge(request.code_verifier), code.code_challenge):
            raise TokenError("invalid_grant", "Incorrect code_verifier")

        return await self.provider.exchange_authorization_code(client, code)

    async def refresh_token(self, client: ClientInformation, request: RefreshTokenRequest) -> Any:
        refresh_token = await self.provider.load_refresh_token(client, request.refresh_token)

        if refresh_token is None or refresh_token.client_id != client.client_id:
            raise TokenError("invalid_grant", "Refresh token does not exist")

        if refresh_token.expires_at is not None and refresh_token.expires_at < time.time():
            raise TokenError("invalid_grant", "Refresh token has expired")

        scopes = request.scope.split() if request.scope else refresh_token.scopes

        for scope in scopes:
            if scope not in refresh_token.scopes:
                raise TokenError("invalid_scope", f"Cannot request scope `{scope}` not granted to the refresh token")

        return await self.provider.exchange_refresh_token(client, refresh_token, scopes)


# Registration endpoint (RFC 7591)


class RegistrationRequest(ClientMetadata):
    """`ClientMetadata` as this server accepts it: the grants it has, with PKCE, nothing less."""

    grant_types: list[str] = Field(default_factory=lambda: list(DEFAULT_GRANT_TYPES))
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    # RFC 7591 §2.3: a JWT of metadata signed by a party the server trusts; taken out before validation.
    software_statement: str | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def _consistent(self) -> RegistrationRequest:
        if unsupported := set(self.grant_types) - set(SUPPORTED_GRANT_TYPES):
            raise ValueError(f"grant_types not supported: {', '.join(sorted(unsupported))}")

        if set(self.grant_types) <= {"refresh_token"}:
            raise ValueError("grant_types must include a grant that obtains tokens")

        if unsupported := set(self.response_types) - {"code"}:
            raise ValueError(f"response_types not supported: {', '.join(sorted(unsupported))}")

        if "authorization_code" in self.grant_types and "code" not in self.response_types:
            raise ValueError("the authorization_code grant needs the code response type")

        # RFC 6749 §3.1.2: no fragment in a redirect URI; RFC 7591 §2: `jwks` and `jwks_uri` never together.
        if any(uri.fragment is not None for uri in self.redirect_uris):
            raise ValueError("redirect_uris must not include a fragment")

        if self.jwks is not None and self.jwks_uri is not None:
            raise ValueError("jwks and jwks_uri must not both be present")

        return self


def registration_response(client: ClientInformation, *, status_code: int = status.HTTP_200_OK) -> Response:
    return model_response(client, status_code=status_code, headers=NO_STORE)


def public_view(client: ClientInformation) -> ClientInformation:
    # Stored hashed, so neither can be read back (RFC 7592 §3.1 leaves both optional).
    return client.model_copy(update={"client_secret": None, "registration_access_token": None})


@dataclass
class RegistrationEndpoint:
    provider: AuthorizationServerProvider
    options: ClientRegistrationOptions
    # The endpoint's own URL, under which RFC 7592 configuration URLs are issued.
    url: str | None = None

    async def handle(self, request: Request) -> Response:
        try:
            metadata = await self.parse(await request.body())
            client = self.client(metadata)
            await self.provider.register_client(self.hashed(client))
        except ValidationError as e:
            return oauth_error_response(RegistrationError("invalid_client_metadata", describe(e)))
        except RegistrationError as e:
            return oauth_error_response(e)

        return registration_response(client, status_code=status.HTTP_201_CREATED)

    async def parse(self, body: bytes) -> RegistrationRequest:
        metadata = RegistrationRequest.model_validate_json(body)

        if metadata.software_statement is None:
            return metadata

        # The statement's claims win over the request's (RFC 7591 §3.1).
        statement = self.software_statement_claims(metadata.software_statement)
        return RegistrationRequest.model_validate({**metadata.model_dump(mode="json", exclude_none=True), **statement})

    def software_statement_claims(self, statement: str) -> dict[str, Any]:
        if self.options.software_statement_key is None:
            raise RegistrationError("unapproved_software_statement", "Software statements are not accepted")

        try:
            import jwt
        except ImportError as e:
            raise MissingExtra("jwt", "Software statements") from e

        try:
            return jwt.decode(
                statement,
                self.options.software_statement_key,
                algorithms=self.options.software_statement_algorithms,
                options={"verify_aud": False},
            )
        except jwt.PyJWTError as e:
            raise RegistrationError("invalid_software_statement", f"Software statement did not verify: {e}") from e

    def client(self, metadata: ClientMetadata) -> ClientInformation:
        if metadata.token_endpoint_auth_method is None:
            # RFC 7591 §2: the default when omitted.
            metadata.token_endpoint_auth_method = "client_secret_basic"

        if metadata.scope is None and self.options.default_scopes is not None:
            metadata.scope = " ".join(self.options.default_scopes)
        elif metadata.scope is not None and self.options.valid_scopes is not None:
            unknown = set(metadata.scope.split()) - set(self.options.valid_scopes)

            if unknown:
                raise RegistrationError(
                    "invalid_client_metadata", f"Requested scopes are not valid: {', '.join(sorted(unknown))}"
                )

        issued_at = int(time.time())
        secret = secrets.token_hex(CLIENT_SECRET_BYTES) if metadata.token_endpoint_auth_method != "none" else None
        secret_expires_at = None

        if secret is not None:
            # RFC 7591 §3.2.1: required whenever a secret is issued, `0` meaning it never expires.
            expiry = self.options.client_secret_expiry_seconds
            secret_expires_at = issued_at + expiry if expiry is not None else 0

        client_id = str(uuid4())
        configuration = {}

        if self.options.configuration_endpoint and self.url is not None:
            configuration = {
                "registration_access_token": new_token(),
                "registration_client_uri": f"{self.url}/{client_id}",
            }

        return ClientInformation.model_validate(
            {
                **metadata.model_dump(),
                "client_id": client_id,
                "client_id_issued_at": issued_at,
                "client_secret": secret,
                "client_secret_expires_at": secret_expires_at,
                **configuration,
            }
        )

    @staticmethod
    def hashed(client: ClientInformation) -> ClientInformation:
        # Each credential is handed to the client once; only its digest is kept, as for codes and tokens.
        return client.model_copy(
            update={
                "client_secret": digest(client.client_secret) if client.client_secret is not None else None,
                "registration_access_token": (
                    digest(client.registration_access_token) if client.registration_access_token is not None else None
                ),
            }
        )


# Client configuration endpoint (RFC 7592)


@dataclass
class ClientConfigurationEndpoint:
    provider: AuthorizationServerProvider
    registration: RegistrationEndpoint

    async def handle(self, request: Request) -> Response:
        client = await self.authenticate(request)

        if client is None:
            # RFC 7592 §2.3: the same answer for an unknown client and a bad token.
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, headers=NO_STORE)

        match request.method:
            case "GET":
                return registration_response(public_view(client))
            case "PUT":
                return await self.update(request, client)
            case _:
                await self.provider.delete_client(client.client_id)
                return Response(status_code=status.HTTP_204_NO_CONTENT, headers=NO_STORE)

    async def authenticate(self, request: Request) -> ClientInformation | None:
        client = await self.provider.get_client(request.path_params["client_id"])
        scheme, token = request.headers.get("Authorization", "").partition(" ")[::2]

        if client is None or client.registration_access_token is None or scheme.lower() != "bearer" or not token:
            return None

        stored = client.registration_access_token.encode()

        if not hmac.compare_digest(stored, digest(token).encode()):
            return None

        return client

    async def update(self, request: Request, client: ClientInformation) -> Response:
        try:
            metadata = await self.registration.parse(await request.body())
        except ValidationError as e:
            return oauth_error_response(RegistrationError("invalid_client_metadata", describe(e)))
        except RegistrationError as e:
            return oauth_error_response(e)

        # RFC 7592 §2.2: the metadata is replaced; the credentials and their expiry are not.
        updated = ClientInformation.model_validate(
            {
                **metadata.model_dump(),
                "token_endpoint_auth_method": metadata.token_endpoint_auth_method or client.token_endpoint_auth_method,
                "client_id": client.client_id,
                "client_id_issued_at": client.client_id_issued_at,
                "client_secret": client.client_secret,
                "client_secret_expires_at": client.client_secret_expires_at,
                "registration_access_token": client.registration_access_token,
                "registration_client_uri": client.registration_client_uri,
            }
        )
        await self.provider.register_client(updated)

        return registration_response(public_view(updated))


# Revocation endpoint (RFC 7009)


class TokenRequestWithHint(BaseModel):
    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None
    client_id: str | None = None

    @classmethod
    def parse(cls, form: FormData) -> TokenRequestWithHint:
        try:
            return cls.model_validate(unique(form))
        except ValidationError as e:
            # RFC 7009 §2.2.1: a hint the server does not know is its own error.
            if any(err["loc"] == ("token_type_hint",) for err in e.errors()):
                raise TokenError("unsupported_token_type", describe(e)) from e

            raise TokenError("invalid_request", describe(e)) from e


RevocationRequest = TokenRequestWithHint


@dataclass
class RevocationEndpoint:
    provider: AuthorizationServerProvider
    clients: ClientAuthenticator

    async def handle(self, request: Request) -> Response:
        form = await form_data(request)

        try:
            client = await self.clients.authenticate(request, form)
            revocation = RevocationRequest.parse(form)
        except OAuthError as e:
            return oauth_error_response(e)

        token = await find_token(self.provider, client, revocation)

        # Unknown tokens are a success too (RFC 7009 §2.2).
        if token is not None and token.client_id == client.client_id:
            await self.provider.revoke_token(token)

        return Response(status_code=status.HTTP_200_OK, headers=NO_STORE)


async def find_token(
    provider: AuthorizationServerProvider, client: ClientInformation, request: TokenRequestWithHint
) -> AccessToken | RefreshToken | None:
    if request.token_type_hint == "refresh_token":
        return await provider.load_refresh_token(client, request.token) or (
            await provider.load_access_token(request.token)
        )

    return await provider.load_access_token(request.token) or (await provider.load_refresh_token(client, request.token))


# Introspection endpoint (RFC 7662)


@dataclass
class IntrospectionEndpoint:
    provider: AuthorizationServerProvider
    clients: ClientAuthenticator
    options: IntrospectionOptions

    async def handle(self, request: Request) -> Response:
        form = await form_data(request)

        try:
            client = await self.clients.authenticate(request, form)
            introspection = TokenRequestWithHint.parse(form)
        except OAuthError as e:
            return oauth_error_response(e)

        # RFC 7662 §2.3: a caller not allowed to look, like an unknown token, learns only `active: false`.
        allowed = self.options.clients is None or client.client_id in self.options.clients
        token = await find_token(self.provider, client, introspection) if allowed else None

        return JSONResponse(self.payload(token), headers=NO_STORE)

    @staticmethod
    def payload(token: AccessToken | RefreshToken | None) -> dict[str, Any]:
        if token is None or (token.expires_at is not None and token.expires_at < time.time()):
            return {"active": False}

        claims = dict(token.claims or {}) if isinstance(token, AccessToken) else {}
        # RFC 7662 §2.2: the registered members, over whatever else the token carries.
        claims |= {
            "active": True,
            "client_id": token.client_id,
            "scope": " ".join(token.scopes) or None,
            "sub": token.subject,
            "exp": token.expires_at,
            "aud": token.resource,
            "token_type": "Bearer" if isinstance(token, AccessToken) else "refresh_token",
        }
        return {key: value for key, value in claims.items() if value is not None}


# Device authorization endpoint (RFC 8628 §3.1)


class DeviceAuthorizationRequest(BaseModel):
    scope: str | None = None
    resource: str | None = None
    client_id: str | None = None


@dataclass
class DeviceAuthorizationEndpoint:
    provider: AuthorizationServerProvider
    clients: ClientAuthenticator
    options: DeviceAuthorizationOptions

    async def handle(self, request: Request) -> Response:
        form = await form_data(request)

        try:
            client = await self.clients.authenticate(request, form)
            device = DeviceAuthorizationRequest.model_validate(unique(form))

            if DEVICE_CODE_GRANT not in client.grant_types:
                raise TokenError("unauthorized_client", "Client was not registered for the device code grant")

            try:
                scopes = client.validate_scope(device.scope) or []
            except AuthorizeError as e:
                raise TokenError("invalid_scope", e.description) from e

            authorization = await self.provider.start_device_authorization(
                client, scopes, device.resource, self.options
            )
        except OAuthError as e:
            return oauth_error_response(e)
        except ValidationError as e:
            return oauth_error_response(TokenError("invalid_request", describe(e)))

        return model_response(authorization, headers=NO_STORE)
