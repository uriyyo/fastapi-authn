from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from fastapi_authn.oauth.verifiers.oidc import OIDCVerifier

__all__ = [
    "EntraVerifier",
]

LOGIN_URL: Final = "https://login.microsoftonline.com"
# Multi-tenant endpoints whose discovery names no single issuer; the token's `iss` is then taken as is.
MULTI_TENANT: Final = ("common", "organizations", "consumers")


@dataclass(kw_only=True)
class EntraVerifier(OIDCVerifier):
    """`audience` is the API's application ID URI or client id; `tenant` is its id, or `common` for any tenant.

    Only tokens whose `accessTokenAcceptedVersion` is 2 fit; v1.0 tokens come from `sts.windows.net`.
    """

    tenant: str
    issuer: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self.issuer = f"{LOGIN_URL}/{self.tenant}/v2.0"

        if self.tenant in MULTI_TENANT:
            self.options.setdefault("issuer", None)
