from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final, cast
from urllib.parse import urlparse

from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from pydantic import AnyHttpUrl
from starlette.requests import Request

__all__ = [
    "AUTHORIZATION_SERVER_WELL_KNOWN",
    "OPENAI_APPS_CHALLENGE_PATH",
    "OPENID_CONFIGURATION_WELL_KNOWN",
    "PROTECTED_RESOURCE_WELL_KNOWN",
    "add_well_known_route",
    "authorization_server_metadata_paths",
    "build_resource_metadata_url",
    "openai_apps_challenge",
    "protected_resource_metadata_paths",
    "url_path",
]

PROTECTED_RESOURCE_WELL_KNOWN: Final = "/.well-known/oauth-protected-resource"
AUTHORIZATION_SERVER_WELL_KNOWN: Final = "/.well-known/oauth-authorization-server"
OPENID_CONFIGURATION_WELL_KNOWN: Final = "/.well-known/openid-configuration"
# ChatGPT Apps domain verification: the bare token as plain text.
OPENAI_APPS_CHALLENGE_PATH: Final = "/.well-known/openai-apps-challenge"


def url_path(url: AnyHttpUrl | str) -> str:
    return urlparse(str(url)).path.rstrip("/")


def protected_resource_metadata_paths(resource_url: AnyHttpUrl | str) -> list[str]:
    """RFC 9728: at the resource's path, then at the root, which clients fall back to."""
    paths = [urlparse(str(build_resource_metadata_url(AnyHttpUrl(str(resource_url))))).path]

    if PROTECTED_RESOURCE_WELL_KNOWN not in paths:
        paths.append(PROTECTED_RESOURCE_WELL_KNOWN)

    return paths


def authorization_server_metadata_paths(issuer: AnyHttpUrl | str) -> list[str]:
    """Every location MCP clients probe (RFC 8414 §3.1 and §5): OAuth and OpenID Connect, path-inserted and appended."""
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
    # Browser-based clients (MCP Inspector) read these cross-origin, so they carry CORS like the SDK's.
    endpoint = cast("Any", cors_middleware(handler, ["GET", "OPTIONS"]))
    router.add_route(path, endpoint, methods=["GET", "OPTIONS"], name=name)


def openai_apps_challenge(token: str, *, path: str = OPENAI_APPS_CHALLENGE_PATH) -> APIRouter:
    """Proves the domain to OpenAI's app directory; serve it at the MCP server's host root."""
    router = APIRouter()

    async def challenge(request: Request) -> Response:
        return PlainTextResponse(token)

    router.add_route(path, challenge, methods=["GET"], name="openai_apps_challenge")
    return router
