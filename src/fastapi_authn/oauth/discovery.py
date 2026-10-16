from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final
from urllib.parse import urlparse

from fastapi import APIRouter, Response
from pydantic import AnyHttpUrl
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.routing import request_response

__all__ = [
    "AUTHORIZATION_SERVER_WELL_KNOWN",
    "OPENID_CONFIGURATION_WELL_KNOWN",
    "PROTECTED_RESOURCE_WELL_KNOWN",
    "add_well_known_route",
    "authorization_server_metadata_paths",
    "build_resource_metadata_url",
    "cors_middleware",
    "protected_resource_metadata_paths",
    "url_path",
]

PROTECTED_RESOURCE_WELL_KNOWN: Final = "/.well-known/oauth-protected-resource"
AUTHORIZATION_SERVER_WELL_KNOWN: Final = "/.well-known/oauth-authorization-server"
OPENID_CONFIGURATION_WELL_KNOWN: Final = "/.well-known/openid-configuration"


def url_path(url: AnyHttpUrl | str) -> str:
    return urlparse(str(url)).path.rstrip("/")


def build_resource_metadata_url(resource_url: AnyHttpUrl | str) -> AnyHttpUrl:
    """RFC 9728 §3.1: the well-known segment goes between the host and the resource's path."""
    parsed = urlparse(str(resource_url))
    path = parsed.path if parsed.path != "/" else ""
    return AnyHttpUrl(f"{parsed.scheme}://{parsed.netloc}{PROTECTED_RESOURCE_WELL_KNOWN}{path}")


def cors_middleware(handler: Callable[[Request], Response | Awaitable[Response]], allow_methods: list[str]) -> Any:
    """Lets browser-based clients call an endpoint from any origin; the outermost layer, so errors carry it too.

    An ASGI app, which `add_route` takes as it takes a request handler.
    """
    return CORSMiddleware(
        request_response(handler), allow_origins=["*"], allow_methods=allow_methods, allow_headers=["*"]
    )


def protected_resource_metadata_paths(resource_url: AnyHttpUrl | str) -> list[str]:
    """RFC 9728: at the resource's path, then at the root, which clients fall back to."""
    paths = [urlparse(str(build_resource_metadata_url(resource_url))).path]

    if PROTECTED_RESOURCE_WELL_KNOWN not in paths:
        paths.append(PROTECTED_RESOURCE_WELL_KNOWN)

    return paths


def authorization_server_metadata_paths(issuer: AnyHttpUrl | str) -> list[str]:
    """Every location clients probe (RFC 8414 §3.1 and §5): OAuth and OpenID Connect, path-inserted and appended."""
    match url_path(issuer):
        case "":
            return [AUTHORIZATION_SERVER_WELL_KNOWN, OPENID_CONFIGURATION_WELL_KNOWN]
        case path:
            return [
                f"{AUTHORIZATION_SERVER_WELL_KNOWN}{path}",
                f"{OPENID_CONFIGURATION_WELL_KNOWN}{path}",
                f"{path}{OPENID_CONFIGURATION_WELL_KNOWN}",
            ]


def add_well_known_route(
    router: APIRouter,
    path: str,
    handler: Callable[[Request], Response | Awaitable[Response]],
    *,
    name: str,
) -> None:
    # Browser-based clients read these cross-origin.
    router.add_route(path, cors_middleware(handler, ["GET", "OPTIONS"]), methods=["GET", "OPTIONS"], name=name)
