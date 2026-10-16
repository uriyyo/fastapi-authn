from __future__ import annotations

from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi_authn.exceptions import MissingExtra
from fastapi_authn.oauth.models import AccessToken

try:
    import httpx2
except ImportError as e:
    raise MissingExtra("oidc", "OIDCVerifier") from e

from fastapi_authn.oauth.providers.oidc import discover

from .jwt import JWTVerifier

__all__ = [
    "OIDCVerifier",
]


@dataclass(kw_only=True)
class OIDCVerifier:
    """JWT access tokens from an OpenID Connect issuer, with the signing keys found by discovery.

    Discovery runs in its `lifespan`, which `OAuthBearer` forwards; the first token verified does it otherwise.
    """

    issuer: str
    audience: str | Sequence[str] | None = None
    algorithms: Sequence[str] = ("RS256",)
    leeway: float = 0
    http_client: httpx2.AsyncClient | None = None
    # Overrides for a token layout `JWTVerifier` would not read as is, e.g. `{"issuer": None}`.
    options: dict[str, Any] = field(default_factory=dict)
    # A `JWTVerifier` subclass, for checks beyond what `jwt.decode` does.
    verifier_class: type[JWTVerifier] = JWTVerifier
    _verifier: JWTVerifier | None = field(init=False, default=None, repr=False)

    async def verifier(self) -> JWTVerifier:
        if self._verifier is None:
            metadata = await discover(self.issuer, self.http_client)
            options: dict[str, Any] = {
                "jwks_url": metadata.jwks_uri,
                "issuer": metadata.issuer,
                "audience": self.audience,
                "algorithms": self.algorithms,
                "leeway": self.leeway,
                **self.options,
            }
            self._verifier = self.verifier_class(**options)

        return self._verifier

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        await self.verifier()
        yield

    async def verify_token(self, token: str) -> AccessToken | None:
        verifier = await self.verifier()
        return await verifier.verify_token(token)
