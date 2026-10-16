from __future__ import annotations

from dataclasses import dataclass, field

from fastapi_authn.oauth.verifiers.oidc import OIDCVerifier

__all__ = [
    "KeycloakVerifier",
]


@dataclass(kw_only=True)
class KeycloakVerifier(OIDCVerifier):
    """Keycloak's `aud` is often just `account`; set `audience` to the client whose mapper puts it on tokens."""

    # Where Keycloak serves, e.g. `https://sso.example.com`.
    server_url: str
    realm: str
    issuer: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.issuer = f"{self.server_url.rstrip('/')}/realms/{self.realm}"
