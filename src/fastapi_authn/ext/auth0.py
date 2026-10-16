from __future__ import annotations

from dataclasses import dataclass, field

from fastapi_authn.oauth.verifiers.oidc import OIDCVerifier

__all__ = [
    "Auth0Verifier",
]


@dataclass(kw_only=True)
class Auth0Verifier(OIDCVerifier):
    """`audience` is the API identifier tokens were requested for; without it any token of the tenant passes."""

    # The tenant domain, e.g. `example.us.auth0.com` or a custom one.
    domain: str
    issuer: str = field(init=False, default="")

    def __post_init__(self) -> None:
        # Auth0's issuer carries the trailing slash.
        self.issuer = f"https://{self.domain}/"
