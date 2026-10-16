from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from fastapi_authn.oauth.providers.oauth2 import OAuth2Upstream, UpstreamError
from fastapi_authn.oauth.server import Identity, Transaction
from fastapi_authn.oauth.types import AuthenticationResult

__all__ = [
    "GitHubEmail",
    "GitHubUpstream",
    "GitHubUser",
]


class GitHubUser(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int
    login: str
    name: str | None = None
    email: str | None = None
    avatar_url: str | None = None


class GitHubEmail(BaseModel):
    email: str
    primary: bool = False
    verified: bool = False


EMAILS: TypeAdapter[list[GitHubEmail]] = TypeAdapter(list[GitHubEmail])

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

        try:
            user = GitHubUser.model_validate_json(response.content)
        except ValidationError as e:
            raise UpstreamError("GitHub returned no user") from e

        claims = {
            "login": user.login,
            "name": user.name,
            "email": user.email or await self.primary_email(headers),
            "avatar_url": user.avatar_url,
        }

        return Identity(subject=str(user.id), claims=claims, upstream_tokens=tokens)

    async def primary_email(self, headers: dict[str, str]) -> str | None:
        # Private emails are only listed here, and only with the `user:email` scope.
        if "user:email" not in self.scopes:
            return None

        response = await self.http.get(GITHUB_EMAILS_ENDPOINT, headers=headers)

        if response.is_error:
            return None

        try:
            emails = EMAILS.validate_json(response.content)
        except ValidationError:
            return None

        return next((email.email for email in emails if email.primary and email.verified), None)
