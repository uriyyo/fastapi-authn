from __future__ import annotations

import copy
import inspect
from collections.abc import Awaitable, Callable, Iterator, Sequence
from dataclasses import field
from functools import wraps
from typing import Annotated, Any, Concatenate, Final, Generic, Protocol, TypeAlias, cast

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.utils import get_dependant
from fastapi.openapi.models import APIKey, HTTPBase, OAuth2, OpenIdConnect
from fastapi.security.base import SecurityBase
from fastapi_injected import MakeDataclass, bind_deps
from starlette.authentication import BaseUser
from typing_extensions import ParamSpec, TypeVar

__all__ = [
    "ActorUser",
    "AuthChain",
    "Authenticator",
    "Challenge",
    "SecurityScheme",
    "Verify",
]

# The actor a chain resolves to; unparametrized, anything.
_TActor = TypeVar("_TActor", default=Any)

# Covariant for the protocol; a scheme yielding a narrower credential is still that scheme.
_TCredential_co = TypeVar("_TCredential_co", covariant=True)

_P = ParamSpec("_P")

# Any FastAPI dependency: it reads its credential with FastAPI's own `Security`, `Header` or `Depends`
# parameters and answers with an actor, or `None` when no credential of its kind was sent.
Authenticator: TypeAlias = Callable[..., Awaitable[_TActor | None]]

# Builds the 401 a request without a usable credential gets, from a description; `OAuthBearer.invalid_token`
# is one, carrying the resource metadata a client needs to find the authorization server.
type Challenge = Callable[[str], HTTPException]

# Turns the credential a FastAPI security scheme extracted into an actor, or `None` to refuse it; the
# parameters after the credential are dependencies of its own.
Verify: TypeAlias = Callable[Concatenate[_TCredential_co, _P], Awaitable[_TActor | None]]


class SecurityScheme(Protocol[_TCredential_co]):
    """One of FastAPI's security schemes: an OpenAPI model, and a dependency extracting a credential."""

    model: Any
    scheme_name: str

    async def __call__(self, request: Request) -> _TCredential_co | None: ...


ACTOR_PARAMETER: Final = "actor_{index}"
WWW_AUTHENTICATE: Final = "WWW-Authenticate"


class AuthChain(MakeDataclass, Generic[_TActor], eq=False, kw_only=True):
    """Several ways to authenticate, tried in registration order; the first actor wins.

    Each authenticator is an ordinary FastAPI dependency, so header extraction, OpenAPI security schemes,
    sub-dependencies and `app.dependency_overrides` all come from FastAPI. The chain itself is a dependency:
    `Security(auth)` on a router, `DepFactory[Actor, auth]` in deps, and OpenAPI lists every scheme in it as
    an alternative. It only authenticates; what the actor may do is for the application to decide over it.

    FastAPI resolves every authenticator on every request, so two schemes reading the same header both
    verify a credential they are sent; register the cheaper one first.
    """

    # Answers a request without any credential; without one, a 401 whose `WWW-Authenticate` names the
    # HTTP schemes the chain accepts.
    challenge: Challenge | None = None
    # With `False`, no credential resolves to `None`; a bad one is still an error.

    auto_error: bool = True
    authenticators: list[Authenticator[_TActor]] = field(default_factory=list)
    _optional: AuthChain[_TActor] | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        self._rebuild_signature()

    def authenticator(
        self, func: Callable[_P, Awaitable[_TActor | None]], /
    ) -> Callable[_P, Awaitable[_TActor | None]]:
        """Register one way to authenticate; registered later means tried later."""
        self.authenticators.append(func)
        self._rebuild_signature()

        # The optional twin shares the list, so its signature follows.
        if self._optional is not None:
            self._optional._rebuild_signature()

        return func

    def scheme(
        self,
        scheme: SecurityScheme[_TCredential_co],
        *,
        scopes: Sequence[str] | None = None,
    ) -> Callable[[Verify[_TCredential_co, _P, _TActor]], Callable[_P, Awaitable[_TActor | None]]]:
        """Register one of FastAPI's security schemes with the function that turns its credential into an actor.

        `@auth.scheme(HTTPBearer())` on `async def by_token(credentials, ...)`: the first parameter receives
        what the scheme extracted, the rest are dependencies of its own. The scheme never errors on its own;
        a missing credential means this way did not apply.
        """
        scheme = copy.copy(scheme)

        if hasattr(scheme, "auto_error"):
            # FastAPI's schemes raise on a missing credential unless told not to.
            setattr(scheme, "auto_error", False)  # noqa: B010

        def register(verify: Verify[_TCredential_co, _P, _TActor]) -> Callable[_P, Awaitable[_TActor | None]]:
            @wraps(verify)
            async def authenticate(
                credential: _TCredential_co | None, /, *args: _P.args, **kwargs: _P.kwargs
            ) -> _TActor | None:
                if credential is None:
                    return None

                return await verify(credential, *args, **kwargs)

            # The first parameter is the scheme's; the rest keep resolving as the function declared them.
            dependency: Any = Security(cast("Callable[..., Any]", scheme), scopes=scopes)
            return self.authenticator(bind_deps(authenticate, dependency))

        return register

    def _rebuild_signature(self) -> None:
        # One sub-dependency per authenticator, so FastAPI resolves them all and the chain only picks.
        parameters = [
            inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request),
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

    async def __call__(self, request: Request, **actors: Any) -> _TActor | None:
        if (actor := self.resolved_actor(request, actors)) is not None:
            return actor

        if not self.auto_error:
            return None

        raise self.unauthenticated()

    def resolved_actor(self, request: Request, actors: dict[str, Any]) -> _TActor | None:
        # An `AuthenticationMiddleware` with `ChainBackend` may already have decided.
        match request.scope.get("user"):
            case ActorUser(actor=actor):
                return cast("_TActor", actor)
            case _:
                pass

        for index in range(len(self.authenticators)):
            if (actor := actors.get(ACTOR_PARAMETER.format(index=index))) is not None:
                return cast("_TActor", actor)

        return None

    @property
    def schemes(self) -> list[SecurityBase]:
        return [
            dependant.call
            for dependant in walk(get_dependant(path="", call=self))
            if isinstance(dependant.call, SecurityBase)
        ]

    @property
    def www_authenticate(self) -> str:
        challenges: dict[str, None] = {}

        for scheme in self.schemes:
            match scheme.model:
                case HTTPBase(scheme=name):
                    challenges.setdefault(name.title())
                case OAuth2() | OpenIdConnect():
                    challenges.setdefault("Bearer")
                case APIKey():
                    pass

        return ", ".join(challenges) or "Bearer"

    def unauthenticated(self) -> HTTPException:
        if self.challenge is not None:
            return self.challenge("Authentication required")

        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={WWW_AUTHENTICATE: self.www_authenticate},
        )

    @property
    def optional(self) -> AuthChain[_TActor]:
        """The same chain, resolving to `None` instead of a 401 when no credential was sent."""
        if self.auto_error is False:
            return self

        if self._optional is None:
            self._optional = cast(
                "AuthChain[_TActor]",
                AuthChain(challenge=self.challenge, auto_error=False, authenticators=self.authenticators),
            )

        return self._optional


class ActorUser(BaseUser, Generic[_TActor]):
    __match_args__ = ("actor",)

    def __init__(
        self,
        actor: _TActor,
        *,
        display_name: str | None = None,
    ) -> None:
        self.actor = actor
        self._display_name = display_name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self._display_name if self._display_name is not None else str(self.actor)

    @property
    def identity(self) -> str:
        return self.display_name


def walk(dependant: Dependant) -> Iterator[Dependant]:
    # Every dependant below `dependant`, depth first, each once.
    seen: set[int] = set()
    stack = list(reversed(dependant.dependencies))

    while stack:
        current = stack.pop()

        if id(current) in seen:
            continue

        seen.add(id(current))
        yield current
        stack.extend(reversed(current.dependencies))
