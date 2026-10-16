from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from pydantic_core import from_json, to_json

try:
    from redis.asyncio import Redis
except ImportError as e:
    raise ImportError(
        "RedisStorage needs the `oauth-redis` extra: pip install 'fastapi-mcp-toolsets[oauth-redis]'"
    ) from e

__all__ = [
    "RedisStorage",
]


@dataclass
class RedisStorage:
    client: Redis
    prefix: str = "oauth:"

    def key(self, namespace: str, key: str) -> str:
        return f"{self.prefix}{namespace}:{key}"

    async def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        raw = await self.client.get(self.key(namespace, key))
        return decode(raw)

    async def set(self, namespace: str, key: str, value: dict[str, Any], *, ttl: timedelta | None = None) -> None:
        # In milliseconds: `ex` rounds a short TTL down to no expiry at all.
        px = int(ttl.total_seconds() * 1_000) if ttl is not None else None
        await self.client.set(self.key(namespace, key), to_json(value), px=px)

    async def delete(self, namespace: str, key: str) -> None:
        await self.client.delete(self.key(namespace, key))

    async def pop(self, namespace: str, key: str) -> dict[str, Any] | None:
        raw = await self.client.getdel(self.key(namespace, key))
        return decode(raw)


def decode(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None

    return from_json(raw)
