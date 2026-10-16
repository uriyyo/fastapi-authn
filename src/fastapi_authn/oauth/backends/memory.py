from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

__all__ = [
    "MemoryStorage",
]


@dataclass
class MemoryStorage:
    """For one process and tests; everything is lost on restart."""

    records: dict[tuple[str, str], tuple[dict[str, Any], float | None]] = field(default_factory=dict)

    async def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        match self.records.get((namespace, key)):
            case None:
                return None
            case (_, expires_at) if expires_at is not None and expires_at <= time.time():
                del self.records[namespace, key]
                return None
            case (value, _):
                return dict(value)

    async def set(self, namespace: str, key: str, value: dict[str, Any], *, ttl: timedelta | None = None) -> None:
        expires_at = time.time() + ttl.total_seconds() if ttl is not None else None
        self.records[namespace, key] = (dict(value), expires_at)

    async def delete(self, namespace: str, key: str) -> None:
        self.records.pop((namespace, key), None)

    async def pop(self, namespace: str, key: str) -> dict[str, Any] | None:
        value = await self.get(namespace, key)
        await self.delete(namespace, key)
        return value
