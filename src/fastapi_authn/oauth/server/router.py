from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Final

from fastapi import APIRouter, Request, Response
from fastapi.openapi.models import OAuthFlowAuthorizationCode, OAuthFlows
from fastapi.responses import JSONResponse
from pydantic import AnyHttpUrl

from fastapi_authn._lifespan import lifespan_of
from fastapi_authn.exceptions import UserError
from fastapi_authn.oauth.discovery import (
    add_well_known_route,
    authorization_server_metadata_paths,
    cors_middleware,
    url_path,
)
from fastapi_authn.oauth.models import DEVICE_CODE_GRANT, AccessToken, AuthorizationServerMetadata, TokenVerifier
from fastapi_authn.oauth.resource import as_http_url

from .endpoints import (
    AuthorizationEndpoint,
    ClientAuthenticator,
    ClientConfigurationEndpoint,
    DeviceAuthorizationEndpoint,
    IntrospectionEndpoint,
    RegistrationEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
    metadata_response,
)
from .protocol import (
    AuthorizationServerProvider,
    ClientRegistrationOptions,
    DeviceAuthorizationOptions,
    IntrospectionOptions,
    RevocationOptions,
)
from .provider import StoredProvider

__all__ = [
    "AUTHORIZATION_PATH",
    "DEVICE_AUTHORIZATION_PATH",
    "INTROSPECTION_PATH",
    "JWKS_PATH",
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
INTROSPECTION_PATH: Final = "/introspect"
DEVICE_AUTHORIZATION_PATH: Final = "/device_authorization"
JWKS_PATH: Final = "/jwks"

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
    introspection: IntrospectionOptions | None = None
    device_authorization: DeviceAuthorizationOptions | None = None
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

    @property
    def jwks(self) -> dict[str, Any] | None:
        """The JWK Set verifying the access tokens, when the provider signs them with a published key."""
        signer = getattr(self.provider, "signer", None)
        jwk = signer.public_jwk() if signer is not None else None
        return {"keys": [jwk]} if jwk is not None else None

    @cached_property
    def metadata(self) -> AuthorizationServerMetadata:
        registration = self.client_registration or ClientRegistrationOptions()
        revocation = self.revocation or RevocationOptions()
        introspection = self.introspection or IntrospectionOptions()
        device = self.device_authorization or DeviceAuthorizationOptions(verification_uri="")
        grant_types = ["authorization_code", "refresh_token"] + ([DEVICE_CODE_GRANT] if device.enabled else [])

        metadata = AuthorizationServerMetadata(
            issuer=self.issuer,
            authorization_endpoint=self.endpoint_url(AUTHORIZATION_PATH),
            token_endpoint=self.endpoint_url(TOKEN_PATH),
            registration_endpoint=self.endpoint_url(REGISTRATION_PATH) if registration.enabled else None,
            revocation_endpoint=self.endpoint_url(REVOCATION_PATH) if revocation.enabled else None,
            revocation_endpoint_auth_methods_supported=list(CLIENT_AUTH_METHODS) if revocation.enabled else None,
            introspection_endpoint=self.endpoint_url(INTROSPECTION_PATH) if introspection.enabled else None,
            introspection_endpoint_auth_methods_supported=list(CLIENT_AUTH_METHODS) if introspection.enabled else None,
            device_authorization_endpoint=self.endpoint_url(DEVICE_AUTHORIZATION_PATH) if device.enabled else None,
            jwks_uri=self.endpoint_url(JWKS_PATH) if self.jwks is not None else None,
            scopes_supported=registration.valid_scopes,
            response_types_supported=["code"],
            grant_types_supported=grant_types,
            token_endpoint_auth_methods_supported=list(CLIENT_AUTH_METHODS),
            code_challenge_methods_supported=["S256"],
            authorization_response_iss_parameter_supported=True,
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

        # Every endpoint but the authorization one is called by clients, browser-based ones included, so they
        # carry CORS; the authorization endpoint is navigated to.
        router.add_route(
            prefix + AUTHORIZATION_PATH,
            AuthorizationEndpoint(self.provider, issuer=str(self.issuer)).handle,
            methods=["GET", "POST"],
            name="oauth_authorize",
        )

        for path, handler, name, methods in self.client_endpoints():
            router.add_route(prefix + path, cors_middleware(handler, methods), methods=methods, name=name)

        if (jwks := self.jwks) is not None:

            async def serve_jwks(request: Request) -> Response:
                return JSONResponse(jwks, headers={"Cache-Control": "public, max-age=3600"})

            add_well_known_route(router, prefix + JWKS_PATH, serve_jwks, name="oauth_jwks")

        metadata = self.metadata

        async def serve_metadata(request: Request) -> Response:
            return metadata_response(metadata)

        for path in self.metadata_paths:
            add_well_known_route(router, path, serve_metadata, name="oauth_authorization_server_metadata")

        # The upstream's callback, when the provider authenticates users through one.
        if isinstance(self.provider, StoredProvider):
            router.include_router(self.provider.router)

        return router

    def client_endpoints(self) -> list[tuple[str, Callable[[Request], Awaitable[Response]], str, list[str]]]:
        """The endpoints clients call directly, as enabled: `(path, handler, route name, methods)`."""
        clients = ClientAuthenticator(self.provider)
        post = ["POST", "OPTIONS"]
        endpoints = [(TOKEN_PATH, TokenEndpoint(self.provider, clients).handle, "oauth_token", post)]

        if self.client_registration is not None and self.client_registration.enabled:
            registration = RegistrationEndpoint(
                self.provider, self.client_registration, url=str(self.endpoint_url(REGISTRATION_PATH))
            )
            endpoints.append((REGISTRATION_PATH, registration.handle, "oauth_register", post))

            if self.client_registration.configuration_endpoint:
                configuration = ClientConfigurationEndpoint(self.provider, registration)
                methods = ["GET", "PUT", "DELETE", "OPTIONS"]
                endpoints.append(
                    (REGISTRATION_PATH + "/{client_id}", configuration.handle, "oauth_client_configuration", methods)
                )

        if self.revocation is not None and self.revocation.enabled:
            endpoints.append((REVOCATION_PATH, RevocationEndpoint(self.provider, clients).handle, "oauth_revoke", post))

        if self.introspection is not None and self.introspection.enabled:
            introspection = IntrospectionEndpoint(self.provider, clients, self.introspection)
            endpoints.append((INTROSPECTION_PATH, introspection.handle, "oauth_introspect", post))

        if self.device_authorization is not None and self.device_authorization.enabled:
            device = DeviceAuthorizationEndpoint(self.provider, clients, self.device_authorization)
            endpoints.append((DEVICE_AUTHORIZATION_PATH, device.handle, "oauth_device_authorization", post))

        return endpoints

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
