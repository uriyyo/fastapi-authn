from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "IntrospectionVerifier",
    "JWTVerifier",
    "OIDCVerifier",
]

_MODULES = {
    "IntrospectionVerifier": "introspection",
    "JWTVerifier": "jwt",
    "OIDCVerifier": "oidc",
}


def __getattr__(name: str) -> Any:
    # Loaded on first use, so importing this package needs none of the extras.
    if (module := _MODULES.get(name)) is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    return getattr(importlib.import_module(f"{__name__}.{module}"), name)
