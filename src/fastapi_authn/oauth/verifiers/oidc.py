from __future__ import annotations

from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx2
from mcp.server.auth.provider import AccessToken

from fastapi_authn.oauth.providers.oidc import discover

from .jwt import JWTVerifier

__all__ = [
    "OIDCVerifier",
]


@dataclass(kw_only=True)
class OIDCVerifier:
    """JWT access tokens from an OpenID Connect issuer, with the signing keys found by discovery.

    Discovery runs in its `lifespan`, which `OAuthBearer` forwards and `MCPRouter` runs for its dependencies;
    the first token verified does it otherwise.
    """

    issuer: str
    audience: str | Sequence[str] | None = None
    algorithms: Sequence[str] = ("RS256",)
    leeway: float = 0
    http_client: httpx2.AsyncClient | None = None
    # Overrides for a token layout `JWTVerifier` would not read as is.
    options: dict[str, Any] = field(default_factory=dict)
    _verifier: JWTVerifier | None = field(init=False, default=None, repr=False)

    async def verifier(self) -> JWTVerifier:
        if self._verifier is None:
            metadata = await discover(self.issuer, self.http_client)
            self._verifier = JWTVerifier(
                jwks_url=metadata.jwks_uri,
                issuer=metadata.issuer,
                audience=self.audience,
                algorithms=self.algorithms,
                leeway=self.leeway,
                **self.options,
            )

        return self._verifier

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        await self.verifier()
        yield

    async def verify_token(self, token: str) -> AccessToken | None:
        verifier = await self.verifier()
        return await verifier.verify_token(token)
