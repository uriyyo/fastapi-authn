from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic_core import from_json, to_json

from fastapi_authn.oauth.server.storage import OAuthStorage

__all__ = [
    "EncryptedStorage",
]

PAYLOAD_KEY = "encrypted"


@dataclass
class EncryptedStorage:
    """Encrypts records at rest with Fernet; the first key encrypts, every key decrypts (for rotation)."""

    storage: OAuthStorage
    keys: list[bytes | str]
    fernet: MultiFernet = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.fernet = MultiFernet([Fernet(key) for key in self.keys])

    async def get(self, namespace: str, key: str) -> dict[str, Any] | None:
        match await self.storage.get(namespace, key):
            case {"encrypted": str() as payload}:
                return self.decrypt(payload)
            case _:
                return None

    async def set(self, namespace: str, key: str, value: dict[str, Any], *, ttl: timedelta | None = None) -> None:
        await self.storage.set(namespace, key, {PAYLOAD_KEY: self.encrypt(value)}, ttl=ttl)

    async def delete(self, namespace: str, key: str) -> None:
        await self.storage.delete(namespace, key)

    async def pop(self, namespace: str, key: str) -> dict[str, Any] | None:
        match await self.storage.pop(namespace, key):
            case {"encrypted": str() as payload}:
                return self.decrypt(payload)
            case _:
                return None

    def encrypt(self, value: dict[str, Any]) -> str:
        return self.fernet.encrypt(to_json(value)).decode()

    def decrypt(self, payload: str) -> dict[str, Any] | None:
        # A record written under a key that is gone reads as absent, not as an error.
        try:
            return from_json(self.fernet.decrypt(payload.encode()))
        except InvalidToken:
            return None
