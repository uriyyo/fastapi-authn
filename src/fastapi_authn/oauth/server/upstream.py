from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from fastapi import Request

from fastapi_authn.oauth.types import AuthenticationResult, CallbackMode

from .storage import Transaction

__all__ = [
    "Upstream",
]


class Upstream(Protocol):
    """Where the user proves who they are; the provider turns the answer into codes and tokens."""

    callback_methods: Sequence[str]
    callback_mode: CallbackMode

    async def start(self, transaction: Transaction, *, callback_url: str) -> str:
        """Where to send the user; may note what the callback will need in `transaction.extra`."""
        ...

    async def state_of(self, request: Request) -> str | None:
        """The transaction id the callback request carries."""
        ...

    async def complete(
        self, request: Request, transaction: Transaction, *, callback_url: str
    ) -> AuthenticationResult: ...
