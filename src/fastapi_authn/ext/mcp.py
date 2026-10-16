from __future__ import annotations

from collections.abc import AsyncGenerator, Collection
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse
from fastapi.security.base import SecurityBase
from fastapi_injected import MakeDataclass
from pydantic import BaseModel, ValidationError

from fastapi_authn.oauth.bearer import OAuthBearer
from fastapi_authn.oauth.models import AccessToken

__all__ = [
    "OPENAI_APPS_CHALLENGE_PATH",
    "LazyBearer",
    "openai_apps_challenge",
]

TOOLS_CALL: Final = "tools/call"


class ToolParams(BaseModel):
    name: str | None = None


class JsonRpcCall(BaseModel):
    """The parts of a JSON-RPC request that say what it asks for."""

    method: str
    params: ToolParams | None = None

    @property
    def tool(self) -> str | None:
        return self.params.name if self.params is not None else None


# ChatGPT Apps domain verification: the bare token as plain text.
OPENAI_APPS_CHALLENGE_PATH: Final = "/.well-known/openai-apps-challenge"


class LazyBearer(MakeDataclass, SecurityBase, eq=False, kw_only=True):
    """Lazy MCP authentication: anyone may connect and list tools; a protected tool asks for sign-in when called.

    A `tools/call` of a protected tool without a token is a 401 with the discovery challenge, which is what
    makes a client show its sign-in prompt. Everything else passes, with the token if one was sent. Use it on
    the router in place of `Security(bearer)`.
    """

    bearer: OAuthBearer
    # Tool names that need a token; `None` means every tool but `public`.
    protected: Collection[str] | None = None
    public: Collection[str] = ()
    # JSON-RPC methods that need a token regardless, e.g. `resources/read`.
    protected_methods: Collection[str] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        self.model = self.bearer.model
        self.scheme_name = f"{self.bearer.scheme_name}Lazy"

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        async with self.bearer.lifespan(app):
            yield

    def requires_token(self, method: str | None, tool: str | None) -> bool:
        """Whether the request needs a token, or may go unauthenticated."""
        if method in self.protected_methods:
            return True

        if method != TOOLS_CALL or tool is None or tool in self.public:
            return False

        return self.protected is None or tool in self.protected

    async def __call__(self, request: Request) -> AccessToken | None:
        method, tool = await self.describe(request)

        # Anonymous is fine where no token is required; a token that was sent is still checked.
        token = await self.bearer.authenticate(request, auto_error=False)

        if token is None and self.requires_token(method, tool):
            raise self.bearer.invalid_token("Authentication required")

        return token

    async def describe(self, request: Request) -> tuple[str | None, str | None]:
        # Read ahead of the endpoint: Starlette caches the body, and a malformed one is the endpoint's to reject.
        try:
            call = JsonRpcCall.model_validate_json(await request.body())
        except ValidationError:
            return None, None

        return call.method, call.tool


def openai_apps_challenge(token: str, *, path: str = OPENAI_APPS_CHALLENGE_PATH) -> APIRouter:
    """Proves the domain to OpenAI's app directory; serve it at the MCP server's host root."""
    router = APIRouter()

    async def challenge(request: Request) -> Response:
        return PlainTextResponse(token)

    router.add_route(path, challenge, methods=["GET"], name="openai_apps_challenge")
    return router
