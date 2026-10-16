from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import httpx2
from fastapi import status
from mcp.server.auth.provider import AccessToken

__all__ = [
    "IntrospectionVerifier",
]

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class IntrospectionVerifier:
    """Asks the authorization server about each token (RFC 7662); for opaque tokens.

    An answer is kept for `cache_ttl`, or until the token expires if sooner, so a burst of MCP requests is one
    introspection; `None` asks every time.
    """

    endpoint: str
    client_id: str
    client_secret: str
    http_client: httpx2.AsyncClient | None = None
    cache_ttl: timedelta | None = timedelta(seconds=60)
    _cache: dict[str, tuple[AccessToken | None, float]] = field(init=False, default_factory=dict, repr=False)

    async def verify_token(self, token: str) -> AccessToken | None:
        key = hashlib.sha256(token.encode()).hexdigest()

        match self._cache.get(key):
            case (access_token, valid_until) if valid_until > time.time():
                return access_token
            case _:
                pass

        access_token = await self.introspect(token)

        if self.cache_ttl is not None:
            valid_until = time.time() + self.cache_ttl.total_seconds()

            if access_token is not None and access_token.expires_at is not None:
                valid_until = min(valid_until, access_token.expires_at)

            self._cache[key] = (access_token, valid_until)

        return access_token

    async def introspect(self, token: str) -> AccessToken | None:
        response = await self.http.post(
            self.endpoint,
            data={"token": token, "token_type_hint": "access_token"},  # noqa: S106
            auth=httpx2.BasicAuth(self.client_id, self.client_secret),
            headers={"Accept": "application/json"},
        )

        if response.status_code != status.HTTP_200_OK:
            logger.warning("Token introspection failed with status %s", response.status_code)
            return None

        match response.json():
            case {"active": True, **claims}:
                return self.access_token(token, claims)
            case _:
                return None

    def access_token(self, token: str, claims: dict[str, Any]) -> AccessToken | None:
        client_id = claims.get("client_id") or claims.get("azp") or claims.get("sub")

        if client_id is None:
            return None

        match claims.get("scope"):
            case str() as scope:
                scopes = scope.split()
            case [*listed]:
                scopes = [str(scope) for scope in listed]
            case _:
                scopes = []

        aud = claims.get("aud")
        expires_at = claims.get("exp")
        subject = claims.get("sub")

        return AccessToken(
            token=token,
            client_id=str(client_id),
            scopes=scopes,
            expires_at=int(expires_at) if expires_at is not None else None,
            resource=aud if isinstance(aud, str) else None,
            subject=str(subject) if subject is not None else None,
            claims=claims,
        )

    @property
    def http(self) -> httpx2.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx2.AsyncClient(timeout=15)

        return self.http_client
