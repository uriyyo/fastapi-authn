from typing import Any, Protocol, overload

from starlette.types import Lifespan

__all__ = [
    "lifespan_of",
]


class HasLifespan[T](Protocol):
    lifespan: Lifespan[T]


@overload
def lifespan_of[T](obj: HasLifespan[T]) -> Lifespan[T]: ...


@overload
def lifespan_of(obj: Any) -> Lifespan[Any] | None: ...


def lifespan_of(obj: Any) -> Lifespan[Any] | None:
    return getattr(obj, "lifespan", None)
