from __future__ import annotations

from collections.abc import AsyncGenerator, Collection, Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import Request
from fastapi.security.base import SecurityBase
from fastapi_has_permissions import Permission, as_failed, evaluate, is_successful
from fastapi_injected import MakeDataclass, push_inject_scope
from mcp.server.auth.provider import AccessToken
from pydantic import ValidationError
from pydantic_core import from_json

from fastapi_authn.permissions import HasScopes, denied

from .bearer import OAuthBearer

__all__ = [
    "LazyBearer",
]

TOOLS_CALL: Final = "tools/call"

# What a protected tool asks of the caller: the scopes a token needs, or any permission.
type Requirement = Sequence[str] | Permission


class LazyBearer(MakeDataclass, SecurityBase, eq=False, kw_only=True):
    """Lazy authentication: anyone may connect and list tools; a protected tool asks for sign-in when called.

    A `tools/call` of a protected tool without a token is a 401 with the discovery challenge, which is what
    makes a client show its sign-in prompt; a token short of the tool's requirement is a 403 step-up. Everything
    else passes, with the token if one was sent. Use it on the router in place of `Security(bearer)`.
    """

    bearer: OAuthBearer
    # Tool name to what it needs over the bearer's own scopes; `None` means every tool but `public`. A
    # permission is evaluated with this dependency resolving to the request's token.
    protected: Mapping[str, Requirement] | None = None
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

    def requirement(self, method: str | None, tool: str | None) -> Requirement | None:
        """What the request needs a token for, or `None` when it may go unauthenticated."""
        if method in self.protected_methods:
            return self.bearer.scopes

        if method != TOOLS_CALL or tool is None or tool in self.public:
            return None

        if self.protected is None:
            return self.bearer.scopes

        return self.protected.get(tool)

    def permission(self, requirement: Requirement) -> Permission:
        match requirement:
            case Permission() as permission:
                return HasScopes(self, self.bearer.scopes) & permission
            case scopes:
                return HasScopes(self, [*self.bearer.scopes, *scopes])

    def scopes_hint(self, requirement: Requirement) -> Sequence[str]:
        match requirement:
            case Permission():
                return self.bearer.scopes
            case scopes:
                return [*self.bearer.scopes, *scopes]

    async def __call__(self, request: Request) -> AccessToken | None:
        method, tool = await self.describe(request)
        requirement = self.requirement(method, tool)

        if requirement is None:
            # Anonymous is fine here; a token that was sent is still checked.
            return await self.bearer.authenticate(request, required=self.bearer.scopes, auto_error=False)

        token = await self.bearer.authenticate(request, required=(), auto_error=False)

        if token is None:
            raise self.bearer.invalid_token("Authentication required", scopes=self.scopes_hint(requirement))

        # The check may ask for this dependency, which is being resolved right now: answer it with the token.
        async with push_inject_scope({self: token}, request=request, app=request.app):
            result = await evaluate(self.permission(requirement))

        if not is_successful(result):
            raise denied(as_failed(result))

        return token

    async def describe(self, request: Request) -> tuple[str | None, str | None]:
        # Read ahead of the endpoint: Starlette caches the body, and a malformed one is the endpoint's to reject.
        try:
            body: Any = from_json(await request.body())
        except (ValueError, ValidationError):
            return None, None

        match body:
            case {"method": str() as method, "params": {"name": str() as tool}}:
                return method, tool
            case {"method": str() as method}:
                return method, None
            case _:
                return None, None
