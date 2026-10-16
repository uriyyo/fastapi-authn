from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from pydantic import BaseModel, ValidationError

from fastapi_authn.oauth.models import AccessToken
from fastapi_authn.oauth.verifiers.jwt import JWTVerifier

__all__ = [
    "CognitoVerifier",
]

ISSUER: Final = "https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
JWKS_PATH: Final = "/.well-known/jwks.json"


class CognitoClaims(BaseModel):
    token_use: Literal["access", "id"]
    client_id: str | None = None


@dataclass(kw_only=True)
class CognitoVerifier(JWTVerifier):
    """Cognito puts the app client in `client_id` on access tokens and in `aud` on ID tokens; `token_use` tells which.

    `client_ids` are the app clients whose tokens are accepted; empty accepts any client of the pool.
    """

    region: str
    user_pool_id: str
    client_ids: Sequence[str] = ()
    token_use: Literal["access", "id"] = "access"

    jwks_url: str | None = field(init=False, default=None)
    issuer: str | None = field(init=False, default=None)
    audience: str | Sequence[str] | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.issuer = ISSUER.format(region=self.region, user_pool_id=self.user_pool_id)
        self.jwks_url = self.issuer + JWKS_PATH

        if self.token_use == "id" and self.client_ids:
            self.audience = list(self.client_ids)

        super().__post_init__()

    def access_token(self, token: str, claims: dict[str, Any]) -> AccessToken | None:
        try:
            cognito = CognitoClaims.model_validate(claims)
        except ValidationError:
            return None

        if cognito.token_use != self.token_use:
            return None

        if self.token_use == "access" and self.client_ids and cognito.client_id not in self.client_ids:
            return None

        return super().access_token(token, claims)
