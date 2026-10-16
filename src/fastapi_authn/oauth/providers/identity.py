from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import Request
from mcp.server.auth.provider import construct_redirect_uri

from fastapi_authn.oauth.server import Denied, Identity, Transaction
from fastapi_authn.oauth.types import AuthenticationResult, CallbackMode

__all__ = [
    "Authenticate",
    "IdentityUpstream",
]


class Authenticate(Protocol):
    """Turns what the login page posted back into an identity; `None` means it did not check out."""

    async def __call__(self, payload: dict[str, Any], transaction: Transaction, /) -> Identity | None: ...


@dataclass(kw_only=True)
class IdentityUpstream:
    """Your own login page as the upstream: any way of knowing who the user is becomes an authorization server.

    The user is sent to `login_url?state=...`. Once the page has signed them in, it posts
    `{"state": ..., ...}` with whatever `authenticate` needs (an ID token, a session, a one-time code)
    to the callback, or `{"state": ..., "deny": true}`, and is told where to send the user next.
    """

    login_url: str
    authenticate: Authenticate
    state_param: str = "state"

    callback_methods: Sequence[str] = ("POST",)
    callback_mode: CallbackMode = "json"

    async def start(self, transaction: Transaction, *, callback_url: str) -> str:
        return construct_redirect_uri(self.login_url, **{self.state_param: transaction.id})

    async def payload(self, request: Request) -> dict[str, Any]:
        try:
            body = await request.json()
        except ValueError:
            return {}

        return body if isinstance(body, dict) else {}

    async def state_of(self, request: Request) -> str | None:
        payload = await self.payload(request)

        match payload.get(self.state_param):
            case str() as state:
                return state
            case _:
                return None

    async def complete(self, request: Request, transaction: Transaction, *, callback_url: str) -> AuthenticationResult:
        payload = await self.payload(request)

        if payload.get("deny"):
            return Denied()

        if (identity := await self.authenticate(payload, transaction)) is None:
            return Denied(description="Authentication failed")

        return identity
