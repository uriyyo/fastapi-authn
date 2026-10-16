from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import field
from typing import Annotated, Any, Final, Protocol, runtime_checkable

from fastapi import Depends, HTTPException, Request, status
from fastapi_injected import MakeDataclass
from starlette.authentication import BaseUser

__all__ = [
    "AuthChain",
    "Authenticator",
    "Challenger",
    "actor_scopes",
]

# Any FastAPI dependency: it reads its credential with FastAPI's own `Security`, `Header` or `Depends`
# parameters and answers with an actor, or `None` when no credential of its kind was sent.
type Authenticator[A] = Callable[..., Awaitable[A | None]]

ACTOR_PARAMETER: Final = "actor_{index}"


@runtime_checkable
class Challenger(Protocol):
    """Builds the 401 and 403 a request without a usable credential gets; `OAuthBearer` is one."""

    def invalid_token(self, description: str, *, scopes: Sequence[str] = ()) -> HTTPException: ...

    def insufficient_scope(self, missing: Sequence[str], *, scopes: Sequence[str] = ()) -> HTTPException: ...


def actor_scopes(actor: Any) -> Sequence[str]:
    match getattr(actor, "scopes", None):
        case [*scopes]:
            return [str(scope) for scope in scopes]
        case _:
            return ()


class AuthChain(MakeDataclass, eq=False, kw_only=True):
    """Several ways to authenticate, tried in registration order; the first actor wins.

    Each authenticator is an ordinary FastAPI dependency, so header extraction, OpenAPI security schemes,
    sub-dependencies and `app.dependency_overrides` all come from FastAPI. The chain itself is a dependency:
    `Security(auth)` on a router, `DepFactory[Actor, auth]` in deps. It only authenticates; what the actor may
    do is a permission over it, see `IsActor` and `HasScopes`.
    """

    # Answers a request without any credential; without one, a bare `WWW-Authenticate: Bearer` 401.
    challenge: Challenger | None = None
    # With `False`, no credential resolves to `None`; a bad one is still an error.
    auto_error: bool = True
    authenticators: list[Authenticator[Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__post_init__()
        self._rebuild_signature()

    def authenticator[F: Authenticator[Any]](self, func: F, /) -> F:
        """Register one way to authenticate; registered later means tried later."""
        self.authenticators.append(func)
        self._rebuild_signature()

        # The optional twin shares the list, so its signature follows.
        if (optional := getattr(self, "_optional", None)) is not None:
            optional._rebuild_signature()

        return func

    def _rebuild_signature(self) -> None:
        # One sub-dependency per authenticator, so FastAPI resolves them all and the chain only picks.
        parameters = [
            inspect.Parameter(
                "request",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=Request,
            ),
            *(
                inspect.Parameter(
                    ACTOR_PARAMETER.format(index=index),
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=Annotated[Any, Depends(authenticator)],
                )
                for index, authenticator in enumerate(self.authenticators)
            ),
        ]

        self.__signature__ = inspect.Signature(parameters, return_annotation=Any | None)

    async def __call__(self, request: Request, **actors: Any) -> Any | None:
        if (actor := self.resolved_actor(request, actors)) is not None:
            return actor

        if not self.auto_error:
            return None

        raise self.unauthenticated()

    def resolved_actor(self, request: Request, actors: dict[str, Any]) -> Any | None:
        # An `AuthenticationMiddleware` with `ChainBackend` may already have decided.
        match request.scope.get("user"):
            case ActorUser(actor=actor):
                return actor
            case _:
                pass

        for index in range(len(self.authenticators)):
            if (actor := actors.get(ACTOR_PARAMETER.format(index=index))) is not None:
                return actor

        return None

    def unauthenticated(self) -> HTTPException:
        if self.challenge is not None:
            return self.challenge.invalid_token("Authentication required")

        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @property
    def optional(self) -> AuthChain:
        """The same chain, resolving to `None` instead of a 401 when no credential was sent."""
        if self.auto_error is False:
            return self

        if (optional := getattr(self, "_optional", None)) is None:
            optional = AuthChain(challenge=self.challenge, auto_error=False, authenticators=self.authenticators)
            self._optional = optional

        return optional


class ActorUser(BaseUser):
    """What `ChainBackend` puts in `request.user`: the actor an authenticator produced."""

    def __init__(self, actor: Any) -> None:
        self.actor = actor

    __match_args__ = ("actor",)

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        for attribute in ("subject", "name", "username", "client_id", "identity"):
            if (value := getattr(self.actor, attribute, None)) is not None:
                return str(value)

        return type(self.actor).__name__

    @property
    def identity(self) -> str:
        return self.display_name
