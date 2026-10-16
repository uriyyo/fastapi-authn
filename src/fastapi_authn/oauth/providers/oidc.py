from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio.to_thread
from pydantic import BaseModel, TypeAdapter

from fastapi_authn.exceptions import MissingExtra, UserError

try:
    import httpx2
    import jwt
except ImportError as e:
    raise MissingExtra("oidc", "OIDCUpstream") from e
from fastapi_authn.oauth.server import Identity, Transaction
from fastapi_authn.oauth.types import AuthenticationResult

from .oauth2 import OAuth2Upstream, UpstreamError

__all__ = [
    "OIDCUpstream",
    "ProviderMetadata",
    "discover",
]

logger = logging.getLogger(__name__)

WELL_KNOWN = "/.well-known/openid-configuration"
CLAIMS: TypeAdapter[dict[str, Any]] = TypeAdapter(dict[str, Any])


class ProviderMetadata(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    introspection_endpoint: str | None = None
    id_token_signing_alg_values_supported: list[str] = ["RS256"]


async def discover(issuer: str, http: httpx2.AsyncClient | None = None) -> ProviderMetadata:
    url = issuer.rstrip("/") + WELL_KNOWN

    if http is not None:
        response = await http.get(url)
    else:
        async with httpx2.AsyncClient(timeout=15) as client:
            response = await client.get(url)

    response.raise_for_status()
    return ProviderMetadata.model_validate_json(response.content)


@dataclass(kw_only=True)
class OIDCUpstream(OAuth2Upstream):
    """Any OpenID Connect provider, from its issuer URL: Keycloak, Auth0, Okta, Entra ID, Google and the like.

    The endpoints left out are discovered when the app starts (the upstream's `lifespan`, run through the
    provider's); `await OIDCUpstream.discover(...)` does it eagerly instead.
    """

    issuer: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    userinfo_endpoint: str | None = None
    scopes: tuple[str, ...] = ("openid", "email", "profile")
    algorithms: tuple[str, ...] = ("RS256",)
    # Merges `userinfo` into the claims; the ID token alone is enough for most providers.
    fetch_userinfo: bool = False
    jwks: jwt.PyJWKClient | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if self.jwks_uri is not None:
            self.jwks = jwt.PyJWKClient(self.jwks_uri, cache_keys=True)

    @property
    def discovered(self) -> bool:
        return None not in (self.authorization_endpoint, self.token_endpoint, self.jwks_uri)

    def configure(self, metadata: ProviderMetadata) -> None:
        """Fills in the endpoints not given explicitly from the provider's metadata."""
        self.authorization_endpoint = self.authorization_endpoint or metadata.authorization_endpoint
        self.token_endpoint = self.token_endpoint or metadata.token_endpoint
        self.jwks_uri = self.jwks_uri or metadata.jwks_uri
        self.userinfo_endpoint = self.userinfo_endpoint or metadata.userinfo_endpoint
        self.__post_init__()

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        """Discovers the provider's endpoints at startup, unless they were all given."""
        if not self.discovered:
            metadata = await discover(self.issuer, self.http_client)
            self.configure(metadata)

        yield

    @classmethod
    async def discover(
        cls,
        issuer: str,
        *,
        client_id: str,
        client_secret: str | None = None,
        http_client: httpx2.AsyncClient | None = None,
        **options: Any,
    ) -> OIDCUpstream:
        metadata = await discover(issuer, http_client)

        return cls(
            issuer=metadata.issuer,
            authorization_endpoint=metadata.authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            jwks_uri=metadata.jwks_uri,
            userinfo_endpoint=metadata.userinfo_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            http_client=http_client,
            **options,
        )

    async def identity(self, tokens: dict[str, Any], transaction: Transaction) -> AuthenticationResult:
        match tokens.get("id_token"):
            case str() as id_token:
                claims = await self.verify_id_token(id_token)
            case _:
                raise UpstreamError("The upstream issued no ID token")

        if self.fetch_userinfo and self.userinfo_endpoint is not None:
            userinfo = await self.userinfo(tokens["access_token"])
            claims |= userinfo

        return Identity(subject=str(claims["sub"]), claims=claims, upstream_tokens=tokens)

    async def verify_id_token(self, id_token: str) -> dict[str, Any]:
        if self.jwks is None:
            raise UserError("The OIDC upstream's endpoints are not discovered yet: run it through the app's lifespan")

        key = await anyio.to_thread.run_sync(self.jwks.get_signing_key_from_jwt, id_token)

        try:
            return jwt.decode(
                id_token, key.key, algorithms=list(self.algorithms), audience=self.client_id, issuer=self.issuer
            )
        except jwt.PyJWTError as e:
            raise UpstreamError(f"Invalid ID token: {e}") from e

    async def userinfo(self, access_token: str) -> dict[str, Any]:
        response = await self.http.get(str(self.userinfo_endpoint), headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()
        return CLAIMS.validate_json(response.content)
