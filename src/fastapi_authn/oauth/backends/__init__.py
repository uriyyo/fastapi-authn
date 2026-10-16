from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "EncryptedStorage",
    "MemoryStorage",
    "RedisStorage",
    "SQLAlchemyStorage",
]

_MODULES = {
    "EncryptedStorage": "encrypted",
    "MemoryStorage": "memory",
    "RedisStorage": "redis",
    "SQLAlchemyStorage": "sqlalchemy",
}


def __getattr__(name: str) -> Any:
    if (module := _MODULES.get(name)) is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    return getattr(importlib.import_module(f"{__name__}.{module}"), name)
