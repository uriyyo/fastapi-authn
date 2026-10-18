from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi_authn.exceptions import MissingExtra

try:
    import jwt
except ImportError as e:
    raise MissingExtra("jwt", "AccessTokenSigner") from e

__all__ = [
    "AccessTokenSigner",
]


@dataclass(kw_only=True)
class AccessTokenSigner:
    """Signs access tokens as JWTs (RFC 9068), so a resource server can verify them without the storage.

    `key` is the private key in PEM, or the shared secret for an HMAC algorithm. The public half is served as
    a JWK Set by the authorization server when the algorithm has one.
    """

    key: str | bytes
    algorithm: str = "RS256"
    kid: str | None = None

    def sign(self, claims: dict[str, Any]) -> str:
        headers = {"typ": "at+jwt"} | ({"kid": self.kid} if self.kid is not None else {})
        return jwt.encode(claims, self.key, algorithm=self.algorithm, headers=headers)

    def public_jwk(self) -> dict[str, Any] | None:
        """The verification key as a JWK; `None` for a shared secret, which is never published."""
        if self.algorithm.startswith("HS"):
            return None

        algorithm = jwt.get_algorithm_by_name(self.algorithm)
        key = algorithm.prepare_key(self.key)
        public = key.public_key() if hasattr(key, "public_key") else key
        jwk = algorithm.to_jwk(public, as_dict=True)

        return {**jwk, "use": "sig", "alg": self.algorithm} | ({"kid": self.kid} if self.kid is not None else {})
