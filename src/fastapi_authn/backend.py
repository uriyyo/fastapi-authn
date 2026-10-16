from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request
from fastapi_injected import DependencyResolutionError, push_inject_scope, resolve
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection

from .chain import ActorUser, AuthChain, actor_scopes

__all__ = [
    "ChainBackend",
]

logger = logging.getLogger(__name__)


@dataclass
class ChainBackend(AuthenticationBackend):
    """Runs the chain from Starlette's `AuthenticationMiddleware`, for `request.user` outside FastAPI routes.

    A bad credential leaves the request anonymous here; the route's own `Security(auth)` then answers with
    the proper 401 or 403, and reuses the actor this backend found instead of verifying again.
    """

    chain: AuthChain

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        if conn.scope["type"] != "http":
            return None

        # The same scope as a `Request`; its body is not available here, headers and cookies are.
        async with push_inject_scope(request=Request(conn.scope), app=conn.scope.get("app")):
            try:
                actor = await resolve(self.chain.optional)
            except (HTTPException, DependencyResolutionError):
                return None

        if actor is None:
            return None

        return AuthCredentials([*actor_scopes(actor)]), ActorUser(actor)
