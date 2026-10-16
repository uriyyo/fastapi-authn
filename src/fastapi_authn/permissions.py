from __future__ import annotations

from collections.abc import Iterable
from dataclasses import field
from typing import Any, ClassVar

from fastapi import HTTPException, status
from fastapi_has_permissions import CheckResult, Failed, Permission
from fastapi_has_permissions.types import Dep
from fastapi_injected import is_dep, unwrap_dep_dependency

from .chain import AuthChain, Challenger, actor_scopes

__all__ = [
    "HasScopes",
    "IsActor",
    "denied",
]

INSUFFICIENT_SCOPE: str = "insufficient_scope"


def _frozen(scopes: Iterable[str]) -> frozenset[str]:
    match scopes:
        case str():
            return frozenset((scopes,))
        case _:
            return frozenset(scopes)


def _challenger_of(actor_dep: Any) -> Challenger | None:
    # The bearer challenges itself; a chain carries the challenger it was given.
    dependency = unwrap_dep_dependency(actor_dep) if is_dep(actor_dep) else actor_dep

    match dependency:
        case AuthChain(challenge=challenge):
            return challenge
        case Challenger():
            return dependency
        case _:
            return None


def denied(failed: Failed) -> HTTPException:
    """The HTTP error a failed check stands for, for code that evaluates permissions itself."""
    return HTTPException(
        status_code=failed.status_code or status.HTTP_403_FORBIDDEN,
        detail=failed.reason or "Permission denied",
        headers=failed.headers,
    )


class IsActor(Permission):
    """Passes when the authenticated actor is of `kind`, for routes that accept one way in only."""

    actor_dep: Dep
    kind: type | tuple[type, ...]

    def get_exc_message(self) -> str:
        kinds = self.kind if isinstance(self.kind, tuple) else (self.kind,)
        return self.message or f"{' or '.join(kind.__name__ for kind in kinds)} authentication required"

    async def check_permissions(self, actor: Any, /) -> bool:
        return isinstance(actor, self.kind)


class HasScopes(Permission):
    """Passes when the actor's `scopes` cover these; fails with the OAuth `insufficient_scope` challenge."""

    actor_dep: Dep
    scopes: Iterable[str]
    # Builds the 403; defaults to the bearer or chain behind `actor_dep`.
    challenge: Challenger | None = field(default=None, kw_only=True)

    default_exc_code: ClassVar[str | None] = INSUFFICIENT_SCOPE

    def __post_init__(self) -> None:
        self.scopes = _frozen(self.scopes)

        if self.challenge is None:
            self.challenge = _challenger_of(self.actor_dep)

        super().__post_init__()

    async def check_permissions(self, actor: Any, /) -> CheckResult:
        granted = actor_scopes(actor)
        missing = sorted(scope for scope in self.scopes if scope not in granted)

        if not missing:
            return True

        reason = f"Required scope(s): {' '.join(missing)}"

        if self.challenge is None:
            return Failed(reason=reason, status_code=status.HTTP_403_FORBIDDEN, code=INSUFFICIENT_SCOPE)

        error = self.challenge.insufficient_scope(missing, scopes=sorted(self.scopes))

        return Failed(
            reason=reason, status_code=error.status_code, code=INSUFFICIENT_SCOPE, headers=dict(error.headers or {})
        )
