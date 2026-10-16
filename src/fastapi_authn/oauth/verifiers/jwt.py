from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import anyio.to_thread
from pydantic import ValidationError

from fastapi_authn.exceptions import MissingExtra, UserError
from fastapi_authn.oauth.models import SCOPES, AccessToken, TokenClaims

try:
    import jwt
except ImportError as e:
    raise MissingExtra("jwt", "JWTVerifier") from e

__all__ = [
    "JWTVerifier",
]


@dataclass(kw_only=True)
class JWTVerifier:
    """Verifies JWT access tokens against a JWKS endpoint or a static key."""

    jwks_url: str | None = None
    key: str | bytes | None = None
    algorithms: Sequence[str] = ("RS256",)
    issuer: str | None = None
    audience: str | Sequence[str] | None = None
    leeway: float = 0
    # Only for a local emulator that issues unsigned tokens; never in production.
    verify_signature: bool = True
    # The first claim present wins; a scope claim is a space-separated string or a list.
    scopes_claims: Sequence[str] = ("scope", "scp")
    # An identity provider's user token names no client; `subject` carries the user then.
    client_id_claims: Sequence[str] = ("client_id", "azp")

    _jwks: jwt.PyJWKClient | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if self.verify_signature and (self.jwks_url is None) == (self.key is None):
            raise UserError("Give either jwks_url or key, not both")

        if self.jwks_url is not None:
            self._jwks = jwt.PyJWKClient(self.jwks_url, cache_keys=True)

    async def signing_key(self, token: str) -> Any:
        if self._jwks is None:
            return self.key or ""

        # Fetches over urllib, so off the event loop; keys are cached by the client.
        signing_key = await anyio.to_thread.run_sync(self._jwks.get_signing_key_from_jwt, token)
        return signing_key.key

    async def verify_token(self, token: str) -> AccessToken | None:
        key = await self.signing_key(token) if self.verify_signature else ""

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
                # Without a configured audience, a token naming one is still accepted.
                options={
                    "verify_signature": self.verify_signature,
                    "verify_aud": self.audience is not None,
                },
            )
        except jwt.PyJWTError:
            return None

        return self.access_token(token, claims)

    def access_token(self, token: str, claims: dict[str, Any]) -> AccessToken | None:
        """The token for verified claims; `None` refuses them. Override to check what `jwt.decode` does not."""
        try:
            standard = TokenClaims.model_validate(claims)
        except ValidationError:
            return None

        client_id = next((str(claims[claim]) for claim in self.client_id_claims if claims.get(claim) is not None), None)

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=self.scopes(claims),
            expires_at=standard.exp,
            resource=standard.resource(self.audience),
            subject=standard.sub,
            claims=claims,
        )

    def scopes(self, claims: dict[str, Any]) -> list[str]:
        return next((SCOPES.validate_python(claims[claim]) for claim in self.scopes_claims if claim in claims), [])
