from __future__ import annotations

from typing import Literal

from fastapi import status

__all__ = [
    "AuthorizationErrorCode",
    "AuthorizeError",
    "OAuthError",
    "RegistrationError",
    "RegistrationErrorCode",
    "TokenError",
    "TokenErrorCode",
]

AuthorizationErrorCode = Literal[
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    "invalid_target",
]

TokenErrorCode = Literal[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_target",
]

RegistrationErrorCode = Literal[
    "invalid_redirect_uri",
    "invalid_client_metadata",
    "invalid_software_statement",
    "unapproved_software_statement",
]


class OAuthError(Exception):
    """An OAuth error response (RFC 6749 §5.2): the `error` code and a description, as JSON or redirect params."""

    status_code: int = status.HTTP_400_BAD_REQUEST

    def __init__(self, error: str, description: str | None = None, *, status_code: int | None = None) -> None:
        super().__init__(description or error)
        self.error = error
        self.description = description

        if status_code is not None:
            self.status_code = status_code

    @property
    def params(self) -> dict[str, str]:
        params = {"error": self.error}

        if self.description is not None:
            params["error_description"] = self.description

        return params


class AuthorizeError(OAuthError):
    """Raised by a provider's `authorize`; sent back to the client's redirect URI when there is one."""

    error: AuthorizationErrorCode


class TokenError(OAuthError):
    """Raised while exchanging a grant at the token endpoint."""

    error: TokenErrorCode


class RegistrationError(OAuthError):
    """Raised while registering a client (RFC 7591 §3.2.2)."""

    error: RegistrationErrorCode
