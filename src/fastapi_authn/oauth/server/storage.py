from __future__ import annotations

from datetime import timedelta
from enum import StrEnum
from typing import Protocol

from mcp.server.auth.provider import AuthorizationCode, RefreshToken
from pydantic import AnyUrl, BaseModel, Field

from fastapi_authn.oauth.types import Claims, Record

__all__ = [
    "Denied",
    "Identity",
    "Namespace",
    "OAuthStorage",
    "StoredCode",
    "StoredRefreshToken",
    "Transaction",
]


class Namespace(StrEnum):
    CLIENTS = "clients"
    TRANSACTIONS = "transactions"
    CODES = "codes"
    ACCESS_TOKENS = "access_tokens"
    REFRESH_TOKENS = "refresh_tokens"


class OAuthStorage(Protocol):
    """A namespaced key-value store with expiry; every record is a JSON object."""

    async def get(self, namespace: str, key: str) -> Record | None: ...

    async def set(self, namespace: str, key: str, value: Record, *, ttl: timedelta | None = None) -> None: ...

    async def delete(self, namespace: str, key: str) -> None: ...

    async def pop(self, namespace: str, key: str) -> Record | None:
        """Get and delete at once, so a code or a refresh token is used by one exchange only."""
        ...


class Denied(BaseModel):
    """The user did not, or may not, sign in; sent back to the client as an OAuth error."""

    error: str = "access_denied"
    description: str | None = None


class Identity(BaseModel):
    """Who the upstream says the user is; `claims` end up on every access token issued for the grant."""

    subject: str
    claims: Claims = Field(default_factory=dict)
    # Narrows what the client asked for, e.g. to what the user may do.
    scopes: list[str] | None = None
    # Whatever the upstream handed out, for hooks that need it; never sent to the client.
    upstream_tokens: Claims | None = None


class Transaction(BaseModel):
    """A pending `/authorize` request, keyed by the state sent to the upstream."""

    id: str
    client_id: str
    redirect_uri: AnyUrl
    redirect_uri_provided_explicitly: bool
    code_challenge: str
    scopes: list[str]
    state: str | None = None
    resource: str | None = None
    # The upstream's own bookkeeping for the round trip, e.g. its PKCE verifier.
    extra: Record = Field(default_factory=dict)


class StoredCode(BaseModel):
    code: AuthorizationCode
    identity: Identity


class StoredRefreshToken(BaseModel):
    token: RefreshToken
    identity: Identity
