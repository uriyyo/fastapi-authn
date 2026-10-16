from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import cached_property
from typing import Final

from fastapi import APIRouter
from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
from mcp.shared.auth import ProtectedResourceMetadata
from pydantic import AnyHttpUrl, ConfigDict, TypeAdapter

from .discovery import add_well_known_route, build_resource_metadata_url, protected_resource_metadata_paths

__all__ = [
    "ProtectedResource",
    "as_http_url",
]

# RFC 8414 issuer comparison is exact, so a URL given without a path must not gain a trailing slash.
HTTP_URL: Final = TypeAdapter(
    AnyHttpUrl,
    config=ConfigDict(url_preserve_empty_path=True),
)


def as_http_url(url: AnyHttpUrl | str) -> AnyHttpUrl:
    return HTTP_URL.validate_python(url)


@dataclass(kw_only=True)
class ProtectedResource:
    """RFC 9728 protected resource metadata: the resource's URL and who issues tokens for it."""

    resource_url: AnyHttpUrl | str
    authorization_servers: Sequence[AnyHttpUrl | str]
    scopes_supported: Sequence[str] | None = None
    resource_name: str | None = None
    resource_documentation: AnyHttpUrl | str | None = None
    # Also at `/.well-known/oauth-protected-resource`, the root clients fall back to; off when several
    # resources share a host.
    serve_root: bool = True

    @cached_property
    def metadata(self) -> ProtectedResourceMetadata:
        return ProtectedResourceMetadata(
            resource=as_http_url(self.resource_url),
            authorization_servers=[as_http_url(url) for url in self.authorization_servers],
            scopes_supported=list(self.scopes_supported) if self.scopes_supported is not None else None,
            resource_name=self.resource_name,
            resource_documentation=(
                as_http_url(self.resource_documentation) if self.resource_documentation is not None else None
            ),
        )

    @cached_property
    def metadata_url(self) -> AnyHttpUrl:
        return build_resource_metadata_url(self.metadata.resource)

    @cached_property
    def metadata_paths(self) -> list[str]:
        paths = protected_resource_metadata_paths(self.metadata.resource)
        return paths if self.serve_root else paths[:1]

    @property
    def router(self) -> APIRouter:
        router = APIRouter()
        handler = ProtectedResourceMetadataHandler(self.metadata)

        for path in self.metadata_paths:
            add_well_known_route(router, path, handler.handle, name="oauth_protected_resource_metadata")

        return router
