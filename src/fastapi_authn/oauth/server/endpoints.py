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
from pydantic import AnyUrl, BaseModel, Field, TypeAdapter, ValidationError, field_validator
from starlette.datastructures import FormData, QueryParams, UploadFile

from fastapi_authn.oauth.errors import AuthorizeError, OAuthError, RegistrationError, TokenError
from fastapi_authn.oauth.models import (
    AccessToken,
    AuthorizationParams,
    ClientInformation,
    ClientMetadata,
    RefreshToken,
    construct_redirect_uri,
)

from .protocol import AuthorizationServerProvider, ClientRegistrationOptions

__all__ = [
    "AuthorizationEndpoint",
    "ClientAuthenticator",
    "RegistrationEndpoint",
    "RevocationEndpoint",
    "TokenEndpoint",
    "metadata_response",
    "oauth_error_response",
]

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
        client_id = form_value(form, "client_id")

        if not client_id:
            raise self.rejected("Missing client_id")

        client = await self.provider.get_client(client_id)

        if client is None:
            raise self.rejected("Invalid client_id")

        secret = self.presented_secret(request, form, client)

        if client.client_secret is not None:
            self.check_secret(client, secret)
        elif client.token_endpoint_auth_method not in ("none", None):
            raise self.rejected("Client is registered for secret-based authentication but has no stored secret")

        return client

    def presented_secret(self, request: Request, form: FormData, client: ClientInformation) -> str | None:
        match client.token_endpoint_auth_method:
            case "client_secret_basic":
                return self.basic_secret(request, client.client_id)
            case "client_secret_post":
                return form_value(form, "client_secret")
            case "none" | None:
                return None
            case method:
                raise self.rejected(f"Unsupported auth method: {method}")

    def check_secret(self, client: ClientInformation, secret: str | None) -> None:
        if not secret:
            raise self.rejected("Client secret is required")

        if not hmac.compare_digest((client.client_secret or "").encode(), secret.encode()):
            raise self.rejected("Invalid client_secret")

        if client.client_secret_expires_at and client.client_secret_expires_at < int(time.time()):
            raise self.rejected("Client secret has expired")

    @staticmethod
    def rejected(description: str) -> TokenError:
        return TokenError("invalid_client", description, status_code=status.HTTP_401_UNAUTHORIZED)

    @classmethod
    def basic_secret(cls, request: Request, client_id: str) -> str:
        header = request.headers.get("Authorization", "")

        if not header.startswith("Basic "):
            raise cls.rejected("Missing or invalid Basic authentication in Authorization header")

        try:
            decoded = base64.b64decode(header.removeprefix("Basic ")).decode()
            basic_client_id, _, secret = decoded.partition(":")
        except (UnicodeDecodeError, binascii.Error, ValueError) as e:
            raise cls.rejected("Invalid Basic authentication header") from e

        if unquote(basic_client_id) != client_id:
            raise cls.rejected("Client ID mismatch in Basic auth")

        return unquote(secret)


# Authorization endpoint (RFC 6749 §4.1.1)


class AuthorizationRequest(BaseModel):
    client_id: str
    redirect_uri: AnyUrl | None = None
    response_type: Literal["code"]
    code_challenge: str
    code_challenge_method: Literal["S256"] = "S256"
    state: str | None = None
    scope: str | None = None
    resource: str | None = None


@dataclass
class AuthorizationEndpoint:
    provider: AuthorizationServerProvider

    async def handle(self, request: Request) -> Response:
        params = request.query_params if request.method == "GET" else await form_data(request)
        state = form_value(params, "state")

        try:
            authorization = AuthorizationRequest.model_validate(dict(params))
        except ValidationError as e:
            error = "invalid_request"

            if any(err["loc"] == ("response_type",) for err in e.errors()):
                error = "unsupported_response_type"

            return await self.error(AuthorizeError(error, describe(e)), params, state)

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
            return self.redirect(construct_redirect_uri(str(redirect_uri), **e.params, state=authorization.state))
        except Exception:
            logger.exception("Unexpected error while authorizing")
            error = AuthorizeError("server_error", "An unexpected error occurred")
            return self.redirect(construct_redirect_uri(str(redirect_uri), **error.params, state=authorization.state))

        return self.redirect(location)

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
                return self.redirect(construct_redirect_uri(str(redirect_uri), **error.params, state=state))

        return oauth_error_response(error)

    @staticmethod
    def redirect(location: str) -> Response:
        return RedirectResponse(location, status_code=status.HTTP_302_FOUND, headers=NO_STORE)


# Token endpoint (RFC 6749 §4.1.3, §6)


class AuthorizationCodeRequest(BaseModel):
    grant_type: Literal["authorization_code"]
    code: str
    redirect_uri: AnyUrl | None = None
    client_id: str
    code_verifier: str
    resource: str | None = None


class RefreshTokenRequest(BaseModel):
    grant_type: Literal["refresh_token"]
    refresh_token: str
    scope: str | None = None
    client_id: str
    resource: str | None = None


TokenRequest = Annotated[AuthorizationCodeRequest | RefreshTokenRequest, Field(discriminator="grant_type")]
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

            match token_request:
                case AuthorizationCodeRequest():
                    tokens = await self.authorization_code(client, token_request)
                case RefreshTokenRequest():
                    tokens = await self.refresh_token(client, token_request)
        except OAuthError as e:
            return oauth_error_response(e)

        return model_response(tokens, headers=NO_STORE)

    @staticmethod
    def parse(form: FormData) -> AuthorizationCodeRequest | RefreshTokenRequest:
        try:
            return TOKEN_REQUEST.validate_python(dict(form))
        except ValidationError as e:
            if form_value(form, "grant_type") not in ("authorization_code", "refresh_token"):
                raise TokenError(
                    "unsupported_grant_type", "Supported grant types: authorization_code, refresh_token"
                ) from e

            raise TokenError("invalid_request", describe(e)) from e

    async def authorization_code(self, client: ClientInformation, request: AuthorizationCodeRequest) -> Any:
        if request.grant_type not in client.grant_types:
            raise TokenError("unauthorized_client", "Client was not registered for the authorization_code grant")

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
        if request.grant_type not in client.grant_types:
            raise TokenError("unauthorized_client", "Client was not registered for the refresh_token grant")

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
    """`ClientMetadata` as this server accepts it: the authorization code grant with PKCE, nothing less."""

    @field_validator("grant_types")
    @classmethod
    def _authorization_code(cls, grant_types: list[str]) -> list[str]:
        if "authorization_code" not in grant_types:
            raise ValueError("must include 'authorization_code'")

        return grant_types

    @field_validator("response_types")
    @classmethod
    def _code(cls, response_types: list[str]) -> list[str]:
        if "code" not in response_types:
            raise ValueError("must include 'code'")

        return response_types


@dataclass
class RegistrationEndpoint:
    provider: AuthorizationServerProvider
    options: ClientRegistrationOptions

    async def handle(self, request: Request) -> Response:
        try:
            metadata = RegistrationRequest.model_validate_json(await request.body())
            client = self.client(metadata)
            await self.provider.register_client(client)
        except ValidationError as e:
            return oauth_error_response(RegistrationError("invalid_client_metadata", describe(e)))
        except RegistrationError as e:
            return oauth_error_response(e)

        return model_response(client, status_code=status.HTTP_201_CREATED, headers=NO_STORE)

    def client(self, metadata: ClientMetadata) -> ClientInformation:
        if metadata.token_endpoint_auth_method is None:
            metadata.token_endpoint_auth_method = "client_secret_post"

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

        return ClientInformation.model_validate(
            {
                **metadata.model_dump(),
                "client_id": str(uuid4()),
                "client_id_issued_at": issued_at,
                "client_secret": secret,
                "client_secret_expires_at": secret_expires_at,
            }
        )


# Revocation endpoint (RFC 7009)


class RevocationRequest(BaseModel):
    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None
    client_id: str


@dataclass
class RevocationEndpoint:
    provider: AuthorizationServerProvider
    clients: ClientAuthenticator

    async def handle(self, request: Request) -> Response:
        form = await form_data(request)

        try:
            client = await self.clients.authenticate(request, form)
            revocation = RevocationRequest.model_validate(dict(form))
        except OAuthError as e:
            return oauth_error_response(e)
        except ValidationError as e:
            return oauth_error_response(TokenError("invalid_request", describe(e)))

        token = await self.find(client, revocation)

        # Unknown tokens are a success too (RFC 7009 §2.2).
        if token is not None and token.client_id == client.client_id:
            await self.provider.revoke_token(token)

        return Response(status_code=status.HTTP_200_OK, headers=NO_STORE)

    async def find(self, client: ClientInformation, revocation: RevocationRequest) -> AccessToken | RefreshToken | None:
        if revocation.token_type_hint == "refresh_token":
            return await self.provider.load_refresh_token(client, revocation.token) or (
                await self.provider.load_access_token(revocation.token)
            )

        return await self.provider.load_access_token(revocation.token) or (
            await self.provider.load_refresh_token(client, revocation.token)
        )
