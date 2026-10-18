"""Grant-wide revocation, introspection, client configuration, software statements, device codes, JWT tokens."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_authn.oauth import (
    AuthorizationServer,
    ClientInformation,
    ClientRegistrationOptions,
    Identity,
    StoredProvider,
)
from fastapi_authn.oauth.server.signer import AccessTokenSigner
from fastapi_authn.oauth.verifiers import IntrospectionVerifier

from .conftest import DEVICE_URL, ISSUER, SECRET, authorize, basic, exchange

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def tokens_for(client: TestClient, registered: ClientInformation, pkce: tuple[str, str]) -> tuple[str, dict[str, Any]]:
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)
    response = exchange(client, registered, code, verifier)
    assert response.status_code == 200, response.text
    return code, response.json()


def me(client: TestClient, access_token: str) -> int:
    return client.get("/api/me", headers={"Authorization": f"Bearer {access_token}"}).status_code


# Grants


def test_replayed_code_revokes_every_token_of_the_grant(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    code, tokens = tokens_for(client, registered, pkce)
    assert me(client, tokens["access_token"]) == 200

    replay = exchange(client, registered, code, pkce[0])
    assert replay.json()["error"] == "invalid_grant"
    assert me(client, tokens["access_token"]) == 401

    refresh = client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        headers=basic(registered),
    )
    assert refresh.json()["error"] == "invalid_grant"


def test_revoking_a_refresh_token_revokes_its_access_tokens(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    _, tokens = tokens_for(client, registered, pkce)
    rotated = client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]},
        headers=basic(registered),
    ).json()
    assert me(client, tokens["access_token"]) == 200
    assert me(client, rotated["access_token"]) == 200

    response = client.post(
        "/revoke",
        data={"token": rotated["refresh_token"], "token_type_hint": "refresh_token"},
        headers=basic(registered),
    )
    assert response.status_code == 200
    assert me(client, tokens["access_token"]) == 401
    assert me(client, rotated["access_token"]) == 401


def test_unknown_token_type_hint(client: TestClient, registered: ClientInformation) -> None:
    response = client.post("/revoke", data={"token": "x", "token_type_hint": "id_token"}, headers=basic(registered))
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_token_type"


# Introspection (RFC 7662)


def test_introspection(client: TestClient, registered: ClientInformation, pkce: tuple[str, str]) -> None:
    assert (
        client.get("/.well-known/oauth-authorization-server").json()["introspection_endpoint"] == f"{ISSUER}/introspect"
    )
    _, tokens = tokens_for(client, registered, pkce)

    active = client.post("/introspect", data={"token": tokens["access_token"]}, headers=basic(registered)).json()
    assert active["active"] is True
    assert active["sub"] == "alice"
    assert active["client_id"] == registered.client_id
    assert active["scope"] == "read"
    assert active["aud"] == f"{ISSUER}/api"
    assert active["iss"] == ISSUER
    assert active["token_type"] == "Bearer"
    assert active["email"] == "alice@example.com"

    refresh = client.post(
        "/introspect",
        data={"token": tokens["refresh_token"], "token_type_hint": "refresh_token"},
        headers=basic(registered),
    ).json()
    assert refresh["active"] is True
    assert refresh["token_type"] == "refresh_token"

    assert client.post("/introspect", data={"token": "nope"}, headers=basic(registered)).json() == {"active": False}
    assert client.post("/introspect", data={"token": tokens["access_token"]}).status_code == 401


async def test_introspection_verifier_against_the_server(
    app: FastAPI, client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    _, tokens = tokens_for(client, registered, pkce)
    verifier = IntrospectionVerifier(
        endpoint=f"{ISSUER}/introspect",
        client_id=registered.client_id,
        client_secret=registered.client_secret or "",
        http_client=httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=ISSUER),
    )

    access = await verifier.verify_token(tokens["access_token"])
    assert access is not None
    assert access.subject == "alice"
    assert access.scopes == ["read"]
    assert await verifier.verify_token("nope") is None


# Client configuration (RFC 7592)


def test_client_configuration_endpoint(client: TestClient, registered: ClientInformation) -> None:
    assert str(registered.registration_client_uri) == f"{ISSUER}/register/{registered.client_id}"
    assert registered.registration_access_token
    headers = {"Authorization": f"Bearer {registered.registration_access_token}"}
    url = f"/register/{registered.client_id}"

    read = client.get(url, headers=headers)
    assert read.status_code == 200
    assert read.json()["client_name"] == "t"
    assert "client_secret" not in read.json()
    assert "registration_access_token" not in read.json()

    updated = client.put(url, headers=headers, json={"redirect_uris": ["http://app/other"], "client_name": "renamed"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["client_name"] == "renamed"
    assert updated.json()["client_id"] == registered.client_id
    assert client.get(url, headers=headers).json()["redirect_uris"] == ["http://app/other"]

    # The secret issued at registration still authenticates after the update.
    assert client.post("/revoke", data={"token": "x"}, headers=basic(registered)).status_code == 200

    assert client.get(url, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get(url).status_code == 401
    assert client.put(url, headers=headers, json={"redirect_uris": []}).json()["error"] == "invalid_client_metadata"

    assert client.delete(url, headers=headers).status_code == 204
    assert client.get(url, headers=headers).status_code == 401
    assert client.post("/revoke", data={"token": "x"}, headers=basic(registered)).status_code == 401


# Software statements (RFC 7591 §2.3)


def test_software_statement_claims_win(client: TestClient, sign: Callable[..., str]) -> None:
    statement = sign({"client_name": "Signed App", "software_id": "app-1"})
    response = client.post(
        "/register",
        json={"redirect_uris": ["http://app/cb"], "client_name": "Unsigned", "software_statement": statement},
    )
    assert response.status_code == 201, response.text
    assert response.json()["client_name"] == "Signed App"
    assert response.json()["software_id"] == "app-1"
    assert "software_statement" not in response.json()

    forged = sign({"client_name": "Forged"}, key="not-the-key".ljust(32, "x"))
    response = client.post("/register", json={"redirect_uris": ["http://app/cb"], "software_statement": forged})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_software_statement"


def test_software_statement_without_a_configured_key(provider: StoredProvider, sign: Callable[..., str]) -> None:
    server = AuthorizationServer.stored(provider, client_registration=ClientRegistrationOptions(enabled=True))
    app = FastAPI()
    app.include_router(server.router)

    response = TestClient(app).post(
        "/register", json={"redirect_uris": ["http://app/cb"], "software_statement": sign({"client_name": "x"})}
    )
    assert response.json()["error"] == "unapproved_software_statement"


# Device authorization (RFC 8628)


@pytest.fixture
def device_client(client: TestClient) -> ClientInformation:
    response = client.post(
        "/register",
        json={
            "redirect_uris": ["http://app/cb"],
            "scope": "read",
            "grant_types": [DEVICE_GRANT, "refresh_token"],
            "response_types": [],
            "token_endpoint_auth_method": "none",
        },
    )
    assert response.status_code == 201, response.text
    return ClientInformation.model_validate(response.json())


def poll(client: TestClient, device_client: ClientInformation, device_code: str) -> Any:
    return client.post(
        "/token", data={"grant_type": DEVICE_GRANT, "device_code": device_code, "client_id": device_client.client_id}
    )


async def test_device_flow(client: TestClient, device_client: ClientInformation, provider: StoredProvider) -> None:
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["device_authorization_endpoint"] == f"{ISSUER}/device_authorization"
    assert DEVICE_GRANT in metadata["grant_types_supported"]

    started = client.post(
        "/device_authorization",
        data={"client_id": device_client.client_id, "scope": "read", "resource": f"{ISSUER}/api"},
    )
    assert started.status_code == 200, started.text
    authorization = started.json()
    assert authorization["verification_uri"] == DEVICE_URL
    assert authorization["verification_uri_complete"] == f"{DEVICE_URL}?user_code={authorization['user_code']}"
    assert authorization["interval"] == 1
    assert len(authorization["user_code"]) == 8

    assert poll(client, device_client, authorization["device_code"]).json()["error"] == "authorization_pending"
    assert poll(client, device_client, authorization["device_code"]).json()["error"] == "slow_down"

    description = await provider.describe_device(authorization["user_code"].lower())
    assert description is not None
    assert description.client_id == device_client.client_id
    assert description.scopes == ["read"]

    assert await provider.approve_device(authorization["user_code"], Identity(subject="bob"))
    assert await provider.describe_device(authorization["user_code"]) is None

    await asyncio.sleep(1)
    tokens = poll(client, device_client, authorization["device_code"]).json()
    assert "access_token" in tokens, tokens
    assert "refresh_token" in tokens
    assert me(client, tokens["access_token"]) == 200
    assert client.get("/api/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()["sub"] == "bob"

    assert poll(client, device_client, authorization["device_code"]).json()["error"] == "invalid_grant"


async def test_device_flow_denied_and_unknown_codes(
    client: TestClient, device_client: ClientInformation, registered: ClientInformation, provider: StoredProvider
) -> None:
    authorization = client.post("/device_authorization", data={"client_id": device_client.client_id}).json()

    assert await provider.deny_device(authorization["user_code"])
    assert not await provider.deny_device("NOPE")
    assert poll(client, device_client, authorization["device_code"]).json()["error"] == "access_denied"
    assert poll(client, device_client, "unknown").json()["error"] == "invalid_grant"

    # A client without the grant may neither start nor poll.
    response = client.post("/device_authorization", data={"client_id": registered.client_id}, headers=basic(registered))
    assert response.json()["error"] == "unauthorized_client"
    bad_scope = client.post("/device_authorization", data={"client_id": device_client.client_id, "scope": "admin"})
    assert bad_scope.json()["error"] == "invalid_scope"


# JWT access tokens (RFC 9068)


def test_hmac_signed_access_tokens(
    provider: StoredProvider, client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    provider.signer = AccessTokenSigner(key=SECRET, algorithm="HS256")
    _, tokens = tokens_for(client, registered, pkce)

    assert jwt.get_unverified_header(tokens["access_token"])["typ"] == "at+jwt"
    claims = jwt.decode(tokens["access_token"], SECRET, algorithms=["HS256"], audience=f"{ISSUER}/api")
    assert claims["iss"] == ISSUER
    assert claims["sub"] == "alice"
    assert claims["client_id"] == registered.client_id
    assert claims["scope"] == "read"
    assert claims["jti"]
    assert claims["exp"] > claims["iat"]
    assert me(client, tokens["access_token"]) == 200

    # No public key, so none is published.
    assert "jwks_uri" not in client.get("/.well-known/oauth-authorization-server").json()


def test_rsa_signed_access_tokens_publish_a_jwk_set(
    provider: StoredProvider, pkce: tuple[str, str], resource: Any, bearer: Any
) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    provider.signer = AccessTokenSigner(key=pem, algorithm="RS256", kid="k1")
    server = AuthorizationServer.stored(provider, client_registration=ClientRegistrationOptions(enabled=True))

    app = FastAPI()
    app.include_router(server.router)
    client = TestClient(app)

    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["jwks_uri"] == f"{ISSUER}/jwks"
    jwks = client.get("/jwks").json()
    assert jwks["keys"][0]["kid"] == "k1"
    assert jwks["keys"][0]["alg"] == "RS256"
    assert "d" not in jwks["keys"][0]

    registered = ClientInformation.model_validate(
        client.post(
            "/register",
            json={
                "redirect_uris": ["http://app/cb"],
                "scope": "read",
                "token_endpoint_auth_method": "client_secret_basic",
            },
        ).json()
    )
    _, tokens = tokens_for(client, registered, pkce)
    key = jwt.PyJWK.from_dict(jwks["keys"][0]).key
    assert jwt.decode(tokens["access_token"], key, algorithms=["RS256"], audience=f"{ISSUER}/api")["sub"] == "alice"
