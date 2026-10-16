from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .server.storage import Denied, Identity

__all__ = [
    "AuthenticationResult",
    "BearerErrorCode",
    "CallbackMode",
    "Claims",
    "Record",
]

# What an upstream, or an identity hook, decided about the user. Evaluated lazily, so no import cycle.
type AuthenticationResult = Identity | Denied

# How a callback answers: send the browser on, or tell a page that posted via `fetch` where to go.
type CallbackMode = Literal["redirect", "json"]

# RFC 6750 error codes a bearer challenge may carry.
type BearerErrorCode = Literal["invalid_token", "insufficient_scope"]

# A token's claims, and a storage record: JSON objects.
type Claims = dict[str, Any]
type Record = dict[str, Any]
