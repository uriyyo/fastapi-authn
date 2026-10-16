from __future__ import annotations

from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass
from functools import cached_property
from typing import Any

from fastapi import APIRouter
from fastapi.openapi.models import OAuthFlowAuthorizationCode, OAuthFlows
from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.provider import OAuthAuthorizationServerProvider, ProviderTokenVerifier, TokenVerifier
from mcp.server.auth.routes import build_metadata, create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthMetadata
from pydantic import AnyHttpUrl

from fastapi_authn._lifespan import lifespan_of
from fastapi_authn.oauth.discovery import (
    AUTHORIZATION_SERVER_WELL_KNOWN,
    add_well_known_route,
    authorization_server_metadata_paths,
    url_path,
)
from fastapi_authn.oauth.resource import as_http_url

from .provider import StoredProvider

__all__ = [
    "AuthorizationServer",
]


@dataclass(kw_only=True)
class AuthorizationServer:
    """The SDK's OAuth authorization server endpoints, served from an `APIRouter`."""

    provider: OAuthAuthorizationServerProvider[Any, Any, Any]
    issuer_url: AnyHttpUrl | str
    service_documentation_url: AnyHttpUrl | str | None = None
    client_registration: ClientRegistrationOptions | None = None
    revocation: RevocationOptions | None = None
    identity_assertion_enabled: bool = False
    # Fields the SDK does not set, e.g. `{"token_endpoint_auth_methods_supported": ["none"]}`.
    metadata_overrides: Mapping[str, Any] | None = None

    @classmethod
    def stored(cls, provider: StoredProvider, **options: Any) -> AuthorizationServer:
        """For a `StoredProvider`, which already knows its issuer URL."""
        return cls(provider=provider, issuer_url=provider.issuer, **options)

    @cached_property
    def issuer(self) -> AnyHttpUrl:
        return as_http_url(self.issuer_url)

    @cached_property
    def metadata(self) -> OAuthMetadata:
        metadata = build_metadata(
            self.issuer,
            as_http_url(self.service_documentation_url) if self.service_documentation_url is not None else None,
            self.client_registration or ClientRegistrationOptions(),
            self.revocation or RevocationOptions(),
            supports_identity_assertion=self.identity_assertion_enabled,
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
        """The provider's lifespan, when it declares one; `MCPRouter` runs it as part of its own."""
        lifespan = lifespan_of(self.provider)

        async with lifespan(app) if lifespan is not None else nullcontext():
            yield

    @property
    def router(self) -> APIRouter:
        # The SDK's routes as they are: PKCE, client authentication, registration and revocation included.
        router = APIRouter()
        prefix = url_path(self.issuer)

        for route in create_auth_routes(
            self.provider,
            self.issuer,
            service_documentation_url=self.metadata.service_documentation,
            client_registration_options=self.client_registration,
            revocation_options=self.revocation,
            identity_assertion_enabled=self.identity_assertion_enabled,
        ):
            # The SDK serves the metadata at the root only; it is served at every probed path below.
            if route.path == AUTHORIZATION_SERVER_WELL_KNOWN:
                continue

            # The SDK mounts the endpoints at the root, while the metadata puts them under the issuer's path.
            router.add_route(prefix + route.path, route.endpoint, methods=list(route.methods or ()), name=route.name)

        handler = MetadataHandler(self.metadata)
        for path in self.metadata_paths:
            add_well_known_route(router, path, handler.handle, name="oauth_authorization_server_metadata")

        # The upstream's callback, when the provider authenticates users through one.
        if isinstance(self.provider, StoredProvider):
            router.include_router(self.provider.router)

        return router

    @property
    def verifier(self) -> TokenVerifier:
        return ProviderTokenVerifier(self.provider)

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
