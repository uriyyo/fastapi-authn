from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta

from fastapi import status
from pydantic import ValidationError

from fastapi_authn.exceptions import MissingExtra
from fastapi_authn.oauth.models import AccessToken, TokenClaims

try:
    import httpx2
except ImportError as e:
    raise MissingExtra("introspection", "IntrospectionVerifier") from e

__all__ = [
    "IntrospectionResponse",
    "IntrospectionVerifier",
]

logger = logging.getLogger(__name__)


class IntrospectionResponse(TokenClaims):
    """RFC 7662 §2.2."""

    active: bool


@dataclass(kw_only=True)
class IntrospectionVerifier:
    """Asks the authorization server about each token (RFC 7662); for opaque tokens.

    An answer is kept for `cache_ttl`, or until the token expires if sooner, so a burst of requests is one
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

        try:
            introspection = IntrospectionResponse.model_validate_json(response.content)
        except ValidationError:
            logger.warning("Token introspection returned an unreadable response")
            return None

        return self.access_token(token, introspection) if introspection.active else None

    def access_token(self, token: str, claims: IntrospectionResponse) -> AccessToken | None:
        return AccessToken(
            token=token,
            client_id=claims.client_id or claims.azp,
            scopes=claims.scope,
            expires_at=claims.exp,
            resource=claims.resource(),
            subject=claims.sub,
            claims=claims.model_dump(exclude={"active"}, exclude_none=True),
        )

    @property
    def http(self) -> httpx2.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx2.AsyncClient(timeout=15)

        return self.http_client
