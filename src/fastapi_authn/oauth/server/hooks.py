from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

from fastapi_injected import inject

from fastapi_authn.oauth.models import AccessToken, ClientInformation
from fastapi_authn.oauth.types import AuthenticationResult

from .storage import Denied, Identity, Transaction

__all__ = [
    "AccessTokenHook",
    "IdentityHook",
    "ProviderHooks",
]


class IdentityHook(Protocol):
    """Enriches or refuses what the upstream reported, e.g. "is this user allowed in at all"."""

    async def __call__(
        self, identity: Identity, client: ClientInformation, transaction: Transaction, /
    ) -> AuthenticationResult: ...


class AccessTokenHook(Protocol):
    """Re-checks a stored token on every request, e.g. "is this account still active"; `None` rejects it."""

    async def __call__(self, token: AccessToken, /) -> AccessToken | None: ...


@dataclass
class ProviderHooks:
    """Decorators registering what runs when a user signs in and when a token is used.

    Hooks may take `Dep[...]` parameters after the positional ones; they are resolved per call.
    """

    identity_hooks: list[IdentityHook] = field(default_factory=list)
    access_token_hooks: list[AccessTokenHook] = field(default_factory=list)

    def identity[H: IdentityHook](self, hook: H, /) -> H:
        self.identity_hooks.append(cast("IdentityHook", inject(new_ctx=True)(hook)))
        return hook

    def access_token[H: AccessTokenHook](self, hook: H, /) -> H:
        self.access_token_hooks.append(cast("AccessTokenHook", inject(new_ctx=True)(hook)))
        return hook

    async def run_identity(
        self, identity: Identity, client: ClientInformation, transaction: Transaction
    ) -> AuthenticationResult:
        result: AuthenticationResult = identity

        for hook in self.identity_hooks:
            result = await hook(result, client, transaction)

            if isinstance(result, Denied):
                return result

        return result

    async def run_access_token(self, token: AccessToken) -> AccessToken | None:
        current: AccessToken | None = token

        for hook in self.access_token_hooks:
            if current is None:
                return None

            current = await hook(current)

        return current
