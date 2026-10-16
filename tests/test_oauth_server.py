import base64
from typing import Annotated, Any

import pytest
from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from fastapi_authn import AuthChain
from fastapi_authn.oauth import (
    AccessToken,
    AuthorizationServer,
    ClientInformation,
    Denied,
    Identity,
    OAuthBearer,
    ProtectedResource,
    StoredProvider,
)
from fastapi_authn.oauth.server import Transaction

from .conftest import ISSUER, LOGIN_URL


@pytest.fixture
def app(server: AuthorizationServer, resource: ProtectedResource, bearer: OAuthBearer) -> FastAPI:
    auth = AuthChain[AccessToken](challenge=bearer.invalid_token)
    auth.authenticator(bearer)

    app = FastAPI()
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


# Metadata


def test_authorization_server_metadata(client: TestClient) -> None:
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == ISSUER
    assert metadata["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert metadata["registration_endpoint"] == f"{ISSUER}/register"
    assert metadata["revocation_endpoint"] == f"{ISSUER}/revoke"
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["scopes_supported"] == ["read", "write"]
    assert client.get("/.well-known/openid-configuration").json() == metadata


def test_protected_resource_metadata(client: TestClient) -> None:
    metadata = client.get("/.well-known/oauth-protected-resource/api").json()
    assert metadata == {
        "resource": f"{ISSUER}/api",
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
    }
    assert client.get("/.well-known/oauth-protected-resource").json() == metadata


def test_client_facing_endpoints_carry_cors(client: TestClient) -> None:
    headers = {"Origin": "http://inspector", "Access-Control-Request-Method": "POST"}
    assert client.options("/token", headers=headers).headers["access-control-allow-origin"] == "*"
    assert client.options("/register", headers=headers).headers["access-control-allow-origin"] == "*"


def test_issuer_must_be_https_or_loopback(provider: StoredProvider) -> None:
    with pytest.raises(Exception, match="HTTPS"):
        AuthorizationServer(provider=provider, issuer_url="http://example.com")


# Registration


def test_registration_issues_credentials(registered: ClientInformation) -> None:
    assert registered.client_secret is not None
    assert registered.client_secret_expires_at == 0
    assert registered.token_endpoint_auth_method == "client_secret_basic"


def test_public_client_gets_no_secret(client: TestClient) -> None:
    response = client.post("/register", json={"redirect_uris": ["http://app/cb"], "token_endpoint_auth_method": "none"})
    body = response.json()
    assert response.status_code == 201
    assert "client_secret" not in body
    assert "client_secret_expires_at" not in body


@pytest.mark.parametrize(
    "metadata",
    [
        {"redirect_uris": ["http://app/cb"], "scope": "admin"},
        {"redirect_uris": ["http://app/cb"], "grant_types": ["refresh_token"]},
        {"redirect_uris": ["http://app/cb"], "response_types": ["token"]},
        {"redirect_uris": []},
        {},
    ],
)
def test_registration_rejects_bad_metadata(client: TestClient, metadata: dict[str, Any]) -> None:
    response = client.post("/register", json=metadata)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client_metadata"


# Authorization


def test_authorize_sends_the_user_to_the_login_page_and_back(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)

    response = exchange(client, registered, code, verifier)
    assert response.status_code == 200, response.text
    tokens = response.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["scope"] == "read"
    assert tokens["refresh_token"]

    me = client.get("/api/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    assert me["sub"] == "alice"
    assert me["client"] == registered.client_id
    assert me["scopes"] == ["read"]
    assert me["claims"]["email"] == "alice@example.com"
    assert me["claims"]["iss"] == ISSUER


def test_transaction_describes_the_client_for_the_login_page(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    response = client.get(
        "/authorize",
        params={
            "client_id": registered.client_id,
            "redirect_uri": "http://app/cb",
            "response_type": "code",
            "code_challenge": pkce[1],
            "scope": "read",
        },
        follow_redirects=False,
    )
    state = response.headers["location"].split("state=")[1]

    described = client.get("/oauth/transaction", params={"state": state}).json()
    assert described == {
        "client_id": registered.client_id,
        "client_name": "t",
        "client_uri": None,
        "logo_uri": None,
        "scopes": ["read"],
    }
    assert client.get("/oauth/transaction", params={"state": "nope"}).status_code == 404


def test_unregistered_redirect_uri_never_redirects(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    response = client.get(
        "/authorize",
        params={
            "client_id": registered.client_id,
            "redirect_uri": "http://evil/cb",
            "response_type": "code",
            "code_challenge": pkce[1],
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_unknown_client_is_an_error_page(client: TestClient, pkce: tuple[str, str]) -> None:
    response = client.get(
        "/authorize",
        params={"client_id": "ghost", "response_type": "code", "code_challenge": pkce[1]},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "ghost" in response.json()["error_description"]


def test_errors_a_known_client_can_hear_are_redirected_with_state(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    params = {
        "client_id": registered.client_id,
        "redirect_uri": "http://app/cb",
        "code_challenge": pkce[1],
        "state": "zz",
    }

    scope = client.get(
        "/authorize", params={**params, "response_type": "code", "scope": "admin"}, follow_redirects=False
    )
    assert scope.status_code == 302
    assert "error=invalid_scope" in scope.headers["location"]
    assert "state=zz" in scope.headers["location"]

    response_type = client.get("/authorize", params={**params, "response_type": "token"}, follow_redirects=False)
    assert response_type.status_code == 302
    assert "error=unsupported_response_type" in response_type.headers["location"]


def test_denied_login_redirects_with_access_denied(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    response = client.get(
        "/authorize",
        params={
            "client_id": registered.client_id,
            "redirect_uri": "http://app/cb",
            "response_type": "code",
            "code_challenge": pkce[1],
            "state": "s1",
        },
        follow_redirects=False,
    )
    state = response.headers["location"].split("state=")[1]

    callback = client.post("/oauth/callback", json={"state": state, "deny": True})
    assert callback.json()["redirect_url"] == "http://app/cb?error=access_denied&state=s1"


def test_failed_login_redirects_with_a_description(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    response = client.get(
        "/authorize",
        params={
            "client_id": registered.client_id,
            "redirect_uri": "http://app/cb",
            "response_type": "code",
            "code_challenge": pkce[1],
        },
        follow_redirects=False,
    )
    state = response.headers["location"].split("state=")[1]

    callback = client.post("/oauth/callback", json={"state": state})
    assert "error=access_denied" in callback.json()["redirect_url"]
    assert "Authentication+failed" in callback.json()["redirect_url"]


def test_unknown_or_used_state_is_rejected(client: TestClient) -> None:
    response = client.post("/oauth/callback", json={"state": "nope", "user": "alice"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


# Token endpoint


def test_token_rejects_wrong_verifier_secret_and_replay(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)

    wrong_verifier = exchange(client, registered, code, "nope")
    assert wrong_verifier.status_code == 400
    assert wrong_verifier.json()["error"] == "invalid_grant"

    wrong_secret = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://app/cb",
            "client_id": registered.client_id,
            "code_verifier": verifier,
        },
        headers={"Authorization": "Basic " + base64.b64encode(f"{registered.client_id}:bad".encode()).decode()},
    )
    assert wrong_secret.status_code == 401
    assert wrong_secret.json()["error"] == "invalid_client"

    assert exchange(client, registered, code, verifier).status_code == 200
    assert exchange(client, registered, code, verifier).json()["error"] == "invalid_grant"


def test_token_rejects_a_changed_redirect_uri(
    client: TestClient, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)

    response = exchange(client, registered, code, verifier, redirect_uri="http://app/other")
    assert response.json()["error"] == "invalid_request"


def test_token_rejects_unsupported_grant_and_missing_client(client: TestClient, registered: ClientInformation) -> None:
    response = client.post(
        "/token", data={"grant_type": "password", "client_id": registered.client_id}, headers=basic(registered)
    )
    assert response.json()["error"] == "unsupported_grant_type"

    response = client.post("/token", data={"grant_type": "authorization_code"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


def test_client_secret_post(client: TestClient, pkce: tuple[str, str]) -> None:
    registered = ClientInformation.model_validate(
        client.post("/register", json={"redirect_uris": ["http://app/cb"], "scope": "read"}).json()
    )
    assert registered.token_endpoint_auth_method == "client_secret_post"
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)

    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://app/cb",
            "client_id": registered.client_id,
            "client_secret": registered.client_secret,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text


def test_refresh_rotates_and_narrows(client: TestClient, registered: ClientInformation, pkce: tuple[str, str]) -> None:
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)
    first = exchange(client, registered, code, verifier).json()

    def refresh(token: str, **data: Any) -> Any:
        return client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": token, "client_id": registered.client_id, **data},
            headers=basic(registered),
        )

    second = refresh(first["refresh_token"])
    assert second.status_code == 200, second.text
    assert second.json()["access_token"] != first["access_token"]

    assert refresh(first["refresh_token"]).json()["error"] == "invalid_grant"
    assert refresh(second.json()["refresh_token"], scope="write").json()["error"] == "invalid_scope"
    assert (
        client.get("/api/me", headers={"Authorization": f"Bearer {second.json()['access_token']}"}).status_code == 200
    )


# Revocation


def test_revocation(client: TestClient, registered: ClientInformation, pkce: tuple[str, str]) -> None:
    verifier, challenge = pkce
    code = authorize(client, registered, challenge)
    tokens = exchange(client, registered, code, verifier).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/api/me", headers=headers).status_code == 200

    revoked = client.post(
        "/revoke", data={"token": tokens["access_token"], "client_id": registered.client_id}, headers=basic(registered)
    )
    assert revoked.status_code == 200
    assert client.get("/api/me", headers=headers).status_code == 401

    # Unknown tokens, and the refresh token with its hint, are a success too.
    assert (
        client.post(
            "/revoke", data={"token": "nope", "client_id": registered.client_id}, headers=basic(registered)
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/revoke",
            data={
                "token": tokens["refresh_token"],
                "token_type_hint": "refresh_token",
                "client_id": registered.client_id,
            },
            headers=basic(registered),
        ).status_code
        == 200
    )


# Bearer


def test_bearer_challenges_with_resource_metadata(client: TestClient, resource: ProtectedResource) -> None:
    response = client.get("/api/me")
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    assert f'resource_metadata="{resource.metadata_url}"' in challenge


def test_bearer_rejects_unknown_token(client: TestClient) -> None:
    response = client.get("/api/me", headers={"Authorization": "Bearer junk"})
    assert response.status_code == 401
    assert response.json() == {"detail": {"error": "invalid_token", "error_description": "Invalid or unknown token"}}


# Hooks


def test_identity_hook_can_enrich_or_refuse(
    client: TestClient, provider: StoredProvider, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    @provider.on.identity
    async def only_alice(identity: Identity, client_: ClientInformation, transaction: Transaction) -> Identity | Denied:
        if identity.subject != "alice":
            return Denied(description="Not you")

        return identity.model_copy(update={"claims": {**identity.claims, "role": "admin"}})

    verifier, challenge = pkce
    code = authorize(client, registered, challenge)
    tokens = exchange(client, registered, code, verifier).json()
    me = client.get("/api/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    assert me["claims"]["role"] == "admin"


def test_access_token_hook_runs_on_every_use(
    client: TestClient, provider: StoredProvider, registered: ClientInformation, pkce: tuple[str, str]
) -> None:
    active = {"alice": True}

    @provider.on.access_token
    async def still_active(token: AccessToken) -> AccessToken | None:
        return token if active.get(token.subject or "") else None

    verifier, challenge = pkce
    code = authorize(client, registered, challenge)
    tokens = exchange(client, registered, code, verifier).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    assert client.get("/api/me", headers=headers).status_code == 200
    active["alice"] = False
    assert client.get("/api/me", headers=headers).status_code == 401
