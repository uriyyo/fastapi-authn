from typing import Any

from starlette.types import Lifespan

__all__ = [
    "lifespan_of",
]


def lifespan_of(obj: Any) -> Lifespan[Any] | None:
    """The `lifespan` an object declares, if any."""
    return getattr(obj, "lifespan", None)
