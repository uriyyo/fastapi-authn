from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from fastapi_authn.oauth.models import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    ClientInformation,
    DeviceAuthorization,
    OAuthToken,
    RefreshToken,
)

__all__ = [
    "AuthorizationServerProvider",
    "ClientRegistrationOptions",
    "DeviceAuthorizationOptions",
    "IntrospectionOptions",
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
    # RFC 7592: `/register/{client_id}` for reading, updating and deleting a registration with the
    # `registration_access_token` issued alongside it.
    configuration_endpoint: bool = False
    # RFC 7591 §2.3: the key software statements must be signed with; without one every statement is refused.
    software_statement_key: str | bytes | None = None
    software_statement_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])


class RevocationOptions(BaseModel):
    """Token revocation (RFC 7009) at `/revoke`."""

    enabled: bool = False


class IntrospectionOptions(BaseModel):
    """Token introspection (RFC 7662) at `/introspect`, for resource servers that cannot read the storage."""

    enabled: bool = False
    # The clients allowed to introspect; `None` lets every authenticated client.
    clients: list[str] | None = None


class DeviceAuthorizationOptions(BaseModel):
    """The device authorization grant (RFC 8628) at `/device_authorization`.

    The application serves `verification_uri`: a page where the user signs in and enters the user code, then
    calls the provider's `approve_device` or `deny_device`.
    """

    enabled: bool = False
    verification_uri: str
    interval_seconds: int = 5
    code_ttl_seconds: int = 600


class AuthorizationServerProvider(Protocol):
    """What the endpoints need from whoever keeps clients, grants and tokens.

    The endpoints validate the protocol: PKCE, client authentication, redirect URIs, expiry. The provider
    decides who the user is (`authorize` sends them somewhere to prove it) and mints the tokens.
    """

    # Clients

    async def get_client(self, client_id: str) -> ClientInformation | None: ...

    async def register_client(self, client: ClientInformation) -> None:
        """Keeps a client the registration endpoint created or updated; raises `RegistrationError` to refuse it.

        The secret and registration access token arrive already hashed.
        """
        ...

    async def delete_client(self, client_id: str) -> None: ...

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
        """Forgets a token, and for a refresh token every token of its grant; one already gone is not an error."""
        ...

    # Device authorization (RFC 8628); only called when the server enables it

    async def start_device_authorization(
        self, client: ClientInformation, scopes: list[str], resource: str | None, options: DeviceAuthorizationOptions
    ) -> DeviceAuthorization: ...

    async def exchange_device_code(self, client: ClientInformation, device_code: str) -> OAuthToken:
        """Tokens once the user approved; raises `TokenError` with `authorization_pending`, `slow_down`,
        `expired_token` or `access_denied` otherwise (RFC 8628 §3.5)."""
        ...
