from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel

from fastapi_authn.oauth.models import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    ClientInformation,
    OAuthToken,
    RefreshToken,
)

__all__ = [
    "AuthorizationServerProvider",
    "ClientRegistrationOptions",
    "RevocationOptions",
]


class ClientRegistrationOptions(BaseModel):
    """Dynamic client registration (RFC 7591) at `/register`."""

    enabled: bool = False
    client_secret_expiry_seconds: int | None = None
    # Scopes a client may register with; `None` accepts any.
    valid_scopes: list[str] | None = None
    # Given to a client that registers without asking for any.
    default_scopes: list[str] | None = None


class RevocationOptions(BaseModel):
    """Token revocation (RFC 7009) at `/revoke`."""

    enabled: bool = False


class AuthorizationServerProvider(Protocol):
    """What the endpoints need from whoever keeps clients, grants and tokens.

    The endpoints validate the protocol: PKCE, client authentication, redirect URIs, expiry. The provider
    decides who the user is (`authorize` sends them somewhere to prove it) and mints the tokens.
    """

    # Clients

    async def get_client(self, client_id: str) -> ClientInformation | None: ...

    async def register_client(self, client: ClientInformation) -> None:
        """Keeps a client the registration endpoint just created; raises `RegistrationError` to refuse it."""
        ...

    # Authorization

    async def authorize(self, client: ClientInformation, params: AuthorizationParams) -> str:
        """Where to send the user's browser so they can authenticate; raises `AuthorizeError` to refuse.

        Once the user is known, the provider sends them to `params.redirect_uri` with a code it issued.
        """
        ...

    async def load_authorization_code(self, client: ClientInformation, code: str) -> AuthorizationCode | None: ...

    async def exchange_authorization_code(self, client: ClientInformation, code: AuthorizationCode) -> OAuthToken:
        """Issues tokens for a code the endpoint already checked; raises `TokenError` for a used one."""
        ...

    # Tokens

    async def load_refresh_token(self, client: ClientInformation, token: str) -> RefreshToken | None: ...

    async def exchange_refresh_token(
        self, client: ClientInformation, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        """Issues a new pair and retires the old refresh token; raises `TokenError` for a used one."""
        ...

    async def load_access_token(self, token: str) -> AccessToken | None: ...

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Forgets a token; one already gone is not an error."""
        ...
