import base64
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_authn.oauth import (
    AccessToken,
    AuthorizationServer,
    ClientRegistrationOptions,
    Identity,
    OAuthBearer,
    ProtectedResource,
    RevocationOptions,
    StoredProvider,
    TokenVerifier,
)
from fastapi_authn.oauth.backends import MemoryStorage
from fastapi_authn.oauth.server import Transaction

ISSUER = "http://localhost:8000"
LOGIN_URL = "http://localhost:3000/login"
SECRET = "0123456789abcdef0123456789abcdef"


@dataclass
class User:
    name: str


@dataclass
class StaticVerifier:
    """A `TokenVerifier` answering from a table, for tests that are not about verification."""

    tokens: dict[str, AccessToken]

    async def verify_token(self, token: str) -> AccessToken | None:
        return self.tokens.get(token)


@pytest.fixture
def sign() -> Callable[..., str]:
    def _sign(claims: dict[str, Any], *, key: str = SECRET, algorithm: str = "HS256") -> str:
        return jwt.encode(claims, key, algorithm=algorithm)

    return _sign


@pytest.fixture
def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def provider() -> StoredProvider:
    provider = StoredProvider(storage=MemoryStorage(), issuer_url=ISSUER, login_url=LOGIN_URL)

    @provider.authenticate
    async def authenticate(payload: dict[str, Any], transaction: Transaction) -> Identity | None:
        if "user" not in payload:
            return None

        return Identity(subject=payload["user"], claims={"email": f"{payload['user']}@example.com"})

    return provider


@pytest.fixture
def server(provider: StoredProvider) -> AuthorizationServer:
    return AuthorizationServer.stored(
        provider,
        client_registration=ClientRegistrationOptions(enabled=True, valid_scopes=["read", "write"]),
        revocation=RevocationOptions(enabled=True),
    )


@pytest.fixture
def resource() -> ProtectedResource:
    return ProtectedResource(resource_url=f"{ISSUER}/api", authorization_servers=[ISSUER])


@pytest.fixture
def bearer(server: AuthorizationServer, resource: ProtectedResource) -> OAuthBearer:
    return OAuthBearer(verifier=server.verifier, resource=resource)


@pytest.fixture
def verifier_of() -> Callable[[dict[str, AccessToken]], TokenVerifier]:
    return StaticVerifier


@pytest.fixture
def client_of() -> Callable[[FastAPI], TestClient]:
    def _client(app: FastAPI) -> TestClient:
        return TestClient(app)

    return _client
