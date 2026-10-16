from __future__ import annotations

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

import httpx2
from fastapi import Request, status
from mcp.server.auth.provider import construct_redirect_uri

from fastapi_authn.oauth.server import Denied, Transaction
from fastapi_authn.oauth.types import AuthenticationResult, CallbackMode

__all__ = [
    "OAuth2Upstream",
]

CODE_VERIFIER_KEY: Final = "code_verifier"


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@dataclass(kw_only=True)
class OAuth2Upstream(ABC):
    """An OAuth 2.0 authorization server as the upstream, with the authorization code grant and PKCE.

    Subclasses say who the user is from the tokens it issued.
    """

    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    client_secret: str | None = None
    scopes: Sequence[str] = ()
    pkce: bool = True
    # Sent along with the authorization request, e.g. `{"prompt": "consent"}`.
    authorization_params: dict[str, str] = field(default_factory=dict)
    http_client: httpx2.AsyncClient | None = None

    callback_methods: Sequence[str] = ("GET",)
    callback_mode: CallbackMode = "redirect"

    async def start(self, transaction: Transaction, *, callback_url: str) -> str:
        params: dict[str, str | None] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": callback_url,
            "state": transaction.id,
            "scope": " ".join(self.scopes) or None,
            **self.authorization_params,
        }

        if self.pkce:
            verifier, challenge = pkce_pair()
            transaction.extra[CODE_VERIFIER_KEY] = verifier
            params |= {"code_challenge": challenge, "code_challenge_method": "S256"}

        return construct_redirect_uri(self.authorization_endpoint, **params)

    async def state_of(self, request: Request) -> str | None:
        return request.query_params.get("state")

    async def complete(self, request: Request, transaction: Transaction, *, callback_url: str) -> AuthenticationResult:
        query = request.query_params

        if error := query.get("error"):
            return Denied(error=error, description=query.get("error_description"))

        if (code := query.get("code")) is None:
            return Denied(error="invalid_request", description="The upstream sent no code")

        tokens = await self.exchange_code(code, transaction, callback_url=callback_url)

        return await self.identity(tokens, transaction)

    async def exchange_code(self, code: str, transaction: Transaction, *, callback_url: str) -> dict[str, Any]:
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": callback_url}

        if self.pkce:
            data[CODE_VERIFIER_KEY] = transaction.extra[CODE_VERIFIER_KEY]

        headers = {"Accept": "application/json"}

        if self.client_secret is not None:
            auth = httpx2.BasicAuth(self.client_id, self.client_secret)
            response = await self.http.post(self.token_endpoint, data=data, auth=auth, headers=headers)
        else:
            # A public client identifies itself in the body.
            data["client_id"] = self.client_id
            response = await self.http.post(self.token_endpoint, data=data, headers=headers)

        if response.status_code != status.HTTP_200_OK:
            raise UpstreamError(f"Token exchange failed with status {response.status_code}")

        tokens = response.json()

        if not isinstance(tokens, dict) or "access_token" not in tokens:
            raise UpstreamError("Token exchange returned no access token")

        return tokens

    @abstractmethod
    async def identity(self, tokens: dict[str, Any], transaction: Transaction) -> AuthenticationResult:
        """Who the user is, from the tokens the upstream issued."""

    @property
    def http(self) -> httpx2.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx2.AsyncClient(timeout=15)

        return self.http_client


class UpstreamError(Exception):
    pass
