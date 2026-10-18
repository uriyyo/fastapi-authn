import base64
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Any

import jwt
import pytest
from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from fastapi_authn import AuthChain, add_authn
from fastapi_authn.oauth import (
    AccessToken,
    AuthorizationServer,
    ClientInformation,
    ClientRegistrationOptions,
    DeviceAuthorizationOptions,
    Identity,
    IntrospectionOptions,
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
DEVICE_URL = "http://localhost:3000/device"
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
        client_registration=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["read", "write"],
            configuration_endpoint=True,
            software_statement_key=SECRET,
            software_statement_algorithms=["HS256"],
        ),
        revocation=RevocationOptions(enabled=True),
        introspection=IntrospectionOptions(enabled=True),
        device_authorization=DeviceAuthorizationOptions(enabled=True, verification_uri=DEVICE_URL, interval_seconds=1),
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


# The authorization server as an app, for the OAuth test modules


@pytest.fixture
def app(server: AuthorizationServer, resource: ProtectedResource, bearer: OAuthBearer) -> FastAPI:
    auth = AuthChain[AccessToken](challenge=bearer.invalid_token)
    auth.authenticator(bearer)

    app = FastAPI()

    add_authn(app)
    app.include_router(server.router)
    app.include_router(resource.router)

    @app.get("/api/me")
    async def me(token: Annotated[AccessToken, Security(auth)]) -> dict[str, Any]:
        return {"sub": token.subject, "client": token.client_id, "scopes": token.scopes, "claims": token.claims}

    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture
def registered(client: TestClient) -> ClientInformation:
    response = client.post(
        "/register",
        json={
            "redirect_uris": ["http://app/cb"],
            "client_name": "t",
            "scope": "read write",
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    assert response.status_code == 201, response.text
    return ClientInformation.model_validate(response.json())


def basic(client: ClientInformation) -> dict[str, str]:
    return {
        "Authorization": "Basic " + base64.b64encode(f"{client.client_id}:{client.client_secret}".encode()).decode()
    }


def authorize(client: TestClient, registered: ClientInformation, challenge: str, **params: Any) -> str:
    """Starts the flow and answers the login page; the authorization code."""
    response = client.get(
        "/authorize",
        params={
            "client_id": registered.client_id,
            "redirect_uri": "http://app/cb",
            "response_type": "code",
            "code_challenge": challenge,
            "state": "s1",
            "scope": "read",
            "resource": f"{ISSUER}/api",
            **params,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    assert response.headers["location"].startswith(f"{LOGIN_URL}?state=")
    state = response.headers["location"].split("state=")[1]

    callback = client.post("/oauth/callback", json={"state": state, "user": "alice"})
    assert callback.status_code == 200, callback.text
    location = callback.json()["redirect_url"]
    assert location.startswith("http://app/cb?code=")
    assert "state=s1" in location
    return location.split("code=")[1].split("&")[0]


def exchange(client: TestClient, registered: ClientInformation, code: str, verifier: str, **data: Any) -> Any:
    return client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://app/cb",
            "client_id": registered.client_id,
            "code_verifier": verifier,
            **data,
        },
        headers=basic(registered),
    )
