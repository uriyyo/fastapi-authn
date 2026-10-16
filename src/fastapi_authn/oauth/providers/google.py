from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx2

from .oidc import OIDCUpstream

__all__ = [
    "GOOGLE_ISSUER",
    "GoogleUpstream",
]

GOOGLE_ISSUER = "https://accounts.google.com"


@dataclass(kw_only=True)
class GoogleUpstream(OIDCUpstream):
    """Google sign-in; `access_type=offline` is the way to also get a refresh token from Google."""

    issuer: str = GOOGLE_ISSUER

    @classmethod
    async def discover(  # type: ignore[override]
        cls,
        issuer: str = GOOGLE_ISSUER,
        *,
        client_id: str,
        client_secret: str | None = None,
        http_client: httpx2.AsyncClient | None = None,
        **options: Any,
    ) -> OIDCUpstream:
        return await super().discover(
            issuer, client_id=client_id, client_secret=client_secret, http_client=http_client, **options
        )
