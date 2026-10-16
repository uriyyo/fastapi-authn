from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic_core import from_json, to_json

try:
    from sqlalchemy import Column, DateTime, MetaData, String, Table, Text, delete, select
    from sqlalchemy.ext.asyncio import AsyncEngine
except ImportError as e:
    raise ImportError(
        "SQLAlchemyStorage needs the `oauth-sqlalchemy` extra: pip install 'fastapi-mcp-toolsets[oauth-sqlalchemy]'"
    ) from e

__all__ = [
    "SQLAlchemyStorage",
]

KEY_LENGTH = 255


def storage_table(name: str, metadata: MetaData) -> Table:
    return Table(
        name,
        metadata,
        Column("namespace", String(KEY_LENGTH), primary_key=True),
        Column("key", String(KEY_LENGTH), primary_key=True),
        Column("value", Text, nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=True),
    )


@dataclass
class SQLAlchemyStorage:
    """One table of JSON records; expired rows are dropped when read, and by `purge_expired`."""

    engine: AsyncEngine
    table_name: str = "oauth_storage"
    metadata: MetaData = field(default_factory=MetaData)
    table: Table = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.table = storage_table(self.table_name, self.metadata)

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        """Creates the table and drops expired rows at startup; runs as part of the authorization server's lifespan."""
        await self.create_table()
        await self.purge_expired()
        yield

    async def create_table(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(self.metadata.create_all, tables=[self.table])

    async def purge_expired(self) -> int:
        """Deletes the rows that expired; call it from a schedule when tokens are rarely read again."""
        async with self.engine.begin() as connection:
            result = await connection.execute(delete(self.table).where(self.table.c.expires_at <= datetime.now(UTC)))
            return result.rowcount

    async def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        return await self.read(namespace, key, remove=False)

    async def set(self, namespace: str, key: str, value: dict[str, Any], *, ttl: timedelta | None = None) -> None:
        expires_at = datetime.now(UTC) + ttl if ttl is not None else None

        async with self.engine.begin() as connection:
            await connection.execute(self.where(delete(self.table), namespace, key))
            await connection.execute(
                self.table.insert().values(
                    namespace=namespace, key=key, value=to_json(value).decode(), expires_at=expires_at
                )
            )

    async def delete(self, namespace: str, key: str) -> None:
        async with self.engine.begin() as connection:
            await connection.execute(self.where(delete(self.table), namespace, key))

    async def pop(self, namespace: str, key: str) -> dict[str, Any] | None:
        return await self.read(namespace, key, remove=True)

    async def read(self, namespace: str, key: str, *, remove: bool) -> dict[str, Any] | None:
        async with self.engine.begin() as connection:
            selected = self.where(select(self.table.c.value, self.table.c.expires_at), namespace, key)
            result = await connection.execute(selected)
            row = result.first()

            if row is None:
                return None

            value, expires_at = row
            expired = expires_at is not None and as_utc(expires_at) <= datetime.now(UTC)

            if remove or expired:
                deleted = await connection.execute(self.where(delete(self.table), namespace, key))

                # Two readers may both see the row; only the one whose delete removed it gets the value.
                if remove and deleted.rowcount == 0:
                    return None

            return None if expired else from_json(value)

    def where(self, statement: Any, namespace: str, key: str) -> Any:
        return statement.where(self.table.c.namespace == namespace, self.table.c.key == key)


def as_utc(value: datetime) -> datetime:
    # SQLite hands back naive datetimes.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
