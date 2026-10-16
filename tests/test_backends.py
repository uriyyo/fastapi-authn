from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import fakeredis.aioredis
import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_authn.oauth.backends import EncryptedStorage, MemoryStorage, RedisStorage, SQLAlchemyStorage
from fastapi_authn.oauth.server import OAuthStorage


@pytest.fixture(params=["memory", "encrypted", "redis", "sqlalchemy"])
async def storage(request: pytest.FixtureRequest) -> AsyncIterator[OAuthStorage]:
    match request.param:
        case "memory":
            yield MemoryStorage()
        case "encrypted":
            yield EncryptedStorage(MemoryStorage(), keys=[Fernet.generate_key()])
        case "redis":
            yield RedisStorage(fakeredis.aioredis.FakeRedis())
        case "sqlalchemy":
            engine = create_async_engine("sqlite+aiosqlite:///:memory:")
            sql = SQLAlchemyStorage(engine)

            async with sql.lifespan(None):
                yield sql

            await engine.dispose()


async def test_set_get_delete(storage: OAuthStorage) -> None:
    record: dict[str, Any] = {"a": 1, "nested": {"b": [1, 2]}}
    await storage.set("ns", "k", record)

    assert await storage.get("ns", "k") == record
    assert await storage.get("other", "k") is None
    assert await storage.get("ns", "missing") is None

    await storage.delete("ns", "k")
    assert await storage.get("ns", "k") is None
    await storage.delete("ns", "k")


async def test_pop_is_single_use(storage: OAuthStorage) -> None:
    await storage.set("ns", "k", {"v": 1})
    assert await storage.pop("ns", "k") == {"v": 1}
    assert await storage.pop("ns", "k") is None


async def test_set_replaces(storage: OAuthStorage) -> None:
    await storage.set("ns", "k", {"v": 1})
    await storage.set("ns", "k", {"v": 2})
    assert await storage.get("ns", "k") == {"v": 2}


async def test_expired_records_read_as_absent(storage: OAuthStorage) -> None:
    await storage.set("ns", "k", {"v": 1}, ttl=timedelta(seconds=-1))
    assert await storage.get("ns", "k") is None

    await storage.set("ns", "k", {"v": 1}, ttl=timedelta(hours=1))
    assert await storage.get("ns", "k") == {"v": 1}


async def test_encrypted_storage_hides_records_and_rotates_keys() -> None:
    inner = MemoryStorage()
    old, new = Fernet.generate_key(), Fernet.generate_key()

    await EncryptedStorage(inner, keys=[old]).set("ns", "k", {"secret": 1})
    assert "secret" not in str(await inner.get("ns", "k"))

    rotated = EncryptedStorage(inner, keys=[new, old])
    assert await rotated.get("ns", "k") == {"secret": 1}
    assert await EncryptedStorage(inner, keys=[new]).get("ns", "k") is None


async def test_sqlalchemy_purge_expired() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    storage = SQLAlchemyStorage(engine)
    await storage.create_table()
    await storage.set("ns", "gone", {"v": 1}, ttl=timedelta(seconds=-1))
    await storage.set("ns", "kept", {"v": 1})

    assert await storage.purge_expired() == 1
    assert await storage.get("ns", "kept") == {"v": 1}
    await engine.dispose()
