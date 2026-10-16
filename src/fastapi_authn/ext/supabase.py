from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final

from fastapi_authn.oauth.verifiers.jwt import JWTVerifier

__all__ = [
    "SupabaseVerifier",
]

AUTH_PATH: Final = "/auth/v1"
JWKS_PATH: Final = "/auth/v1/.well-known/jwks.json"


@dataclass(kw_only=True)
class SupabaseVerifier(JWTVerifier):
    """Tokens from `supabase.auth`; the user's id is `subject`, the Postgres role is `claims["role"]`.

    Projects on asymmetric signing keys verify through the project's JWKS; older ones give `jwt_secret`.
    """

    # The project URL, e.g. `https://abcdefgh.supabase.co`.
    url: str
    jwt_secret: str | None = None
    audience: str | Sequence[str] | None = "authenticated"

    jwks_url: str | None = field(init=False, default=None)
    key: str | bytes | None = field(init=False, default=None)
    issuer: str | None = field(init=False, default=None)
    algorithms: Sequence[str] = field(init=False, default=())
    client_id_claims: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        base = self.url.rstrip("/")
        self.issuer = base + AUTH_PATH

        if self.jwt_secret is not None:
            self.key = self.jwt_secret
            self.algorithms = ("HS256",)
        else:
            self.jwks_url = base + JWKS_PATH
            self.algorithms = ("ES256", "RS256")

        super().__post_init__()
