from __future__ import annotations

from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Final

from fastapi import APIRouter, Request, Response
from fastapi.openapi.models import OAuthFlowAuthorizationCode, OAuthFlows
from pydantic import AnyHttpUrl

from fastapi_authn._lifespan import lifespan_of
from fastapi_authn.exceptions import UserError
from fastapi_authn.oauth.discovery import (
    add_well_known_route,
    authorization_server_metadata_paths,
    cors_middleware,
    url_path,
)
from fastapi_authn.oauth.models import AccessToken, AuthorizationServerMetadata, TokenVerifier
from fastapi_authn.oauth.resource import as_http_url

from .endpoints import (
    AuthorizationEndpoint,
    ClientAuthenticator,
    RegistrationEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
    metadata_response,
)
from .protocol import AuthorizationServerProvider, ClientRegistrationOptions, RevocationOptions
from .provider import StoredProvider

__all__ = [
    "AUTHORIZATION_PATH",
    "REGISTRATION_PATH",
    "REVOCATION_PATH",
    "TOKEN_PATH",
    "AuthorizationServer",
    "ProviderVerifier",
]

AUTHORIZATION_PATH: Final = "/authorize"
TOKEN_PATH: Final = "/token"
REGISTRATION_PATH: Final = "/register"
REVOCATION_PATH: Final = "/revoke"

CLIENT_AUTH_METHODS: Final = ["client_secret_post", "client_secret_basic", "none"]
LOOPBACK_HOSTS: Final = ("localhost", "127.0.0.1", "[::1]")


@dataclass
class ProviderVerifier:
    """Verifies the tokens an `AuthorizationServerProvider` issued, for a bearer on the same app."""

    provider: AuthorizationServerProvider

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self.provider.load_access_token(token)


@dataclass(kw_only=True)
class AuthorizationServer:
    """An OAuth 2.1 authorization server over a provider: the endpoints, their metadata, and a verifier."""

    provider: AuthorizationServerProvider
    issuer_url: AnyHttpUrl | str
    service_documentation_url: AnyHttpUrl | str | None = None
    client_registration: ClientRegistrationOptions | None = None
    revocation: RevocationOptions | None = None
    # Fields the metadata does not set on its own, e.g. `{"ui_locales_supported": ["en"]}`.
    metadata_overrides: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        issuer = self.issuer

        # RFC 8414 wants HTTPS; the loopback is let through for development.
        if issuer.scheme != "https" and issuer.host not in LOOPBACK_HOSTS:
            raise UserError("The issuer URL must be HTTPS")

        if issuer.query or issuer.fragment:
            raise UserError("The issuer URL must not have a query string or a fragment")

    @classmethod
    def stored(cls, provider: StoredProvider, **options: Any) -> AuthorizationServer:
        """For a `StoredProvider`, which already knows its issuer URL."""
        return cls(provider=provider, issuer_url=provider.issuer, **options)

    @cached_property
    def issuer(self) -> AnyHttpUrl:
        return as_http_url(self.issuer_url)

    def endpoint_url(self, path: str) -> AnyHttpUrl:
        return as_http_url(str(self.issuer).rstrip("/") + path)

    @cached_property
    def metadata(self) -> AuthorizationServerMetadata:
        registration = self.client_registration or ClientRegistrationOptions()
        revocation = self.revocation or RevocationOptions()

        metadata = AuthorizationServerMetadata(
            issuer=self.issuer,
            authorization_endpoint=self.endpoint_url(AUTHORIZATION_PATH),
            token_endpoint=self.endpoint_url(TOKEN_PATH),
            registration_endpoint=self.endpoint_url(REGISTRATION_PATH) if registration.enabled else None,
            revocation_endpoint=self.endpoint_url(REVOCATION_PATH) if revocation.enabled else None,
            revocation_endpoint_auth_methods_supported=list(CLIENT_AUTH_METHODS) if revocation.enabled else None,
            scopes_supported=registration.valid_scopes,
            response_types_supported=["code"],
            grant_types_supported=["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported=list(CLIENT_AUTH_METHODS),
            code_challenge_methods_supported=["S256"],
            service_documentation=(
                as_http_url(self.service_documentation_url) if self.service_documentation_url is not None else None
            ),
        )

        if self.metadata_overrides:
            metadata = metadata.model_copy(update=dict(self.metadata_overrides))

        return metadata

    @cached_property
    def metadata_paths(self) -> list[str]:
        """Where clients look for the metadata: OAuth and OpenID Connect, path-inserted and appended."""
        return authorization_server_metadata_paths(self.issuer)

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        """The provider's lifespan, when it declares one."""
        lifespan = lifespan_of(self.provider)

        async with lifespan(app) if lifespan is not None else nullcontext():
            yield

    @property
    def router(self) -> APIRouter:
        router = APIRouter()
        prefix = url_path(self.issuer)
        clients = ClientAuthenticator(self.provider)

        # Token, registration and revocation are called by clients, browser-based ones included, so they carry
        # CORS; the authorization endpoint is navigated to.
        router.add_route(
            prefix + AUTHORIZATION_PATH,
            AuthorizationEndpoint(self.provider).handle,
            methods=["GET", "POST"],
            name="oauth_authorize",
        )
        router.add_route(
            prefix + TOKEN_PATH,
            cors_middleware(TokenEndpoint(self.provider, clients).handle, ["POST", "OPTIONS"]),
            methods=["POST", "OPTIONS"],
            name="oauth_token",
        )

        if self.client_registration is not None and self.client_registration.enabled:
            router.add_route(
                prefix + REGISTRATION_PATH,
                cors_middleware(
                    RegistrationEndpoint(self.provider, self.client_registration).handle, ["POST", "OPTIONS"]
                ),
                methods=["POST", "OPTIONS"],
                name="oauth_register",
            )

        if self.revocation is not None and self.revocation.enabled:
            router.add_route(
                prefix + REVOCATION_PATH,
                cors_middleware(RevocationEndpoint(self.provider, clients).handle, ["POST", "OPTIONS"]),
                methods=["POST", "OPTIONS"],
                name="oauth_revoke",
            )

        metadata = self.metadata

        async def serve_metadata(request: Request) -> Response:
            return metadata_response(metadata)

        for path in self.metadata_paths:
            add_well_known_route(router, path, serve_metadata, name="oauth_authorization_server_metadata")

        # The upstream's callback, when the provider authenticates users through one.
        if isinstance(self.provider, StoredProvider):
            router.include_router(self.provider.router)

        return router

    @property
    def verifier(self) -> TokenVerifier:
        return ProviderVerifier(self.provider)

    def flows(self, scopes: Mapping[str, str] | None = None) -> OAuthFlows:
        """The authorization code flow for OpenAPI, so Swagger UI can obtain a token."""
        if scopes is None:
            scopes = {scope: scope for scope in self.metadata.scopes_supported or ()}

        return OAuthFlows(
            authorizationCode=OAuthFlowAuthorizationCode(
                authorizationUrl=str(self.metadata.authorization_endpoint),
                tokenUrl=str(self.metadata.token_endpoint),
                refreshUrl=str(self.metadata.token_endpoint),
                scopes=dict(scopes),
            )
        )
