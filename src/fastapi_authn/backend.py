from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Generic

from fastapi import HTTPException
from fastapi_injected import DependencyResolutionError, InjectionContext, resolve
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.requests import HTTPConnection
from typing_extensions import TypeVar

from .chain import ActorUser, AuthChain
from .exceptions import UserError

__all__ = [
    "AUTHENTICATED",
    "ChainBackend",
]

logger = logging.getLogger(__name__)

# The scope Starlette's `requires("authenticated")` looks for.
AUTHENTICATED = "authenticated"


_TActor = TypeVar("_TActor", default=Any)


@dataclass
class ChainBackend(AuthenticationBackend, Generic[_TActor]):
    """Runs the chain from Starlette's `AuthenticationMiddleware`, for `request.user` outside FastAPI routes.

    A bad credential leaves the request anonymous here; the route's own `Security(auth)` then answers with
    the proper 401, and reuses the actor this backend found instead of verifying again.
    """

    chain: AuthChain[_TActor]
    # What `request.user.display_name` says; by default the actor's `str`.
    display_name: Callable[[_TActor], str] = str

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        if InjectionContext.current() is None:
            raise UserError("ChainBackend needs a prepared app: call add_authn(app)")

        try:
            actor = await resolve(self.chain.optional)
        except (HTTPException, DependencyResolutionError):
            logger.debug("Credential rejected; the request stays anonymous", exc_info=True)
            return None

        if actor is None:
            return None

        return AuthCredentials([AUTHENTICATED]), ActorUser(actor, display_name=self.display_name(actor))
