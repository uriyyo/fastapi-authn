from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi_authn.oauth.server import Identity, Transaction
from fastapi_authn.oauth.types import AuthenticationResult

from .oauth2 import OAuth2Upstream, UpstreamError

__all__ = [
    "GitHubUpstream",
]

GITHUB_AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"  # noqa: S105
GITHUB_USER_ENDPOINT = "https://api.github.com/user"
GITHUB_EMAILS_ENDPOINT = "https://api.github.com/user/emails"


@dataclass(kw_only=True)
class GitHubUpstream(OAuth2Upstream):
    """GitHub OAuth apps: no ID token, so the identity comes from the user API."""

    authorization_endpoint: str = GITHUB_AUTHORIZATION_ENDPOINT
    token_endpoint: str = GITHUB_TOKEN_ENDPOINT
    scopes: tuple[str, ...] = ("read:user", "user:email")
    # GitHub ignores PKCE but tolerates it.
    pkce: bool = False

    async def identity(self, tokens: dict[str, Any], transaction: Transaction) -> AuthenticationResult:
        headers = {
            "Authorization": f"Bearer {tokens['access_token']}",
            "Accept": "application/vnd.github+json",
        }

        response = await self.http.get(GITHUB_USER_ENDPOINT, headers=headers)
        response.raise_for_status()
        user = response.json()

        if not isinstance(user, dict) or "id" not in user:
            raise UpstreamError("GitHub returned no user")

        claims = {
            "login": user.get("login"),
            "name": user.get("name"),
            "email": user.get("email") or await self.primary_email(headers),
            "avatar_url": user.get("avatar_url"),
        }

        return Identity(subject=str(user["id"]), claims=claims, upstream_tokens=tokens)

    async def primary_email(self, headers: dict[str, str]) -> str | None:
        # Private emails are only listed here, and only with the `user:email` scope.
        if "user:email" not in self.scopes:
            return None

        response = await self.http.get(GITHUB_EMAILS_ENDPOINT, headers=headers)

        if response.is_error:
            return None

        for email in response.json():
            if email.get("primary") and email.get("verified"):
                return email.get("email")

        return None
