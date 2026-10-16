from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from fastapi_authn.oauth.verifiers.oidc import OIDCVerifier

__all__ = [
    "OktaVerifier",
]


@dataclass(kw_only=True)
class OktaVerifier(OIDCVerifier):
    """Tokens from a custom authorization server by default; `authorization_server=None` for the org server."""

    # The org domain, e.g. `dev-123456.okta.com`.
    domain: str
    authorization_server: str | None = "default"
    audience: str | Sequence[str] | None = "api://default"
    issuer: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.issuer = f"https://{self.domain}"

        if self.authorization_server is not None:
            self.issuer += f"/oauth2/{self.authorization_server}"
