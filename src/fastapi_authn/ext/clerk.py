from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import BaseModel, ValidationError

from fastapi_authn.oauth.models import AccessToken
from fastapi_authn.oauth.verifiers.jwt import JWTVerifier

__all__ = [
    "ClerkVerifier",
]

JWKS_PATH: Final = "/.well-known/jwks.json"


class ClerkClaims(BaseModel):
    azp: str | None = None
    sid: str | None = None


@dataclass(kw_only=True)
class ClerkVerifier(JWTVerifier):
    """The user is `subject`, the session `claims["sid"]`; `authorized_parties` are the origins allowed in `azp`."""

    # The instance's Frontend API host, e.g. `clerk.example.com` or `xxx.clerk.accounts.dev`.
    frontend_api: str
    authorized_parties: Sequence[str] = ()

    jwks_url: str | None = field(init=False, default=None)
    issuer: str | None = field(init=False, default=None)
    client_id_claims: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        self.issuer = f"https://{self.frontend_api}"
        self.jwks_url = self.issuer + JWKS_PATH
        super().__post_init__()

    def access_token(self, token: str, claims: dict[str, Any]) -> AccessToken | None:
        try:
            clerk = ClerkClaims.model_validate(claims)
        except ValidationError:
            return None

        if self.authorized_parties and clerk.azp is not None and clerk.azp not in self.authorized_parties:
            return None

        return super().access_token(token, claims)
