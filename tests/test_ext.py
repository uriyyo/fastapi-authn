import importlib
import sys
import time
from collections.abc import Callable
from typing import Annotated, Any

import httpx2
import pytest
from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from fastapi_authn import add_authn
from fastapi_authn.exceptions import MissingExtra
from fastapi_authn.ext.auth0 import Auth0Verifier
from fastapi_authn.ext.clerk import ClerkVerifier
from fastapi_authn.ext.cognito import CognitoVerifier
from fastapi_authn.ext.entra import EntraVerifier
from fastapi_authn.ext.firebase import FirebaseSessionVerifier, FirebaseVerifier
from fastapi_authn.ext.github import GitHubUpstream
from fastapi_authn.ext.keycloak import KeycloakVerifier
from fastapi_authn.ext.mcp import LazyBearer, openai_apps_challenge
from fastapi_authn.ext.okta import OktaVerifier
from fastapi_authn.ext.supabase import SupabaseVerifier
from fastapi_authn.oauth import AccessToken, Identity, OAuthBearer, TokenVerifier
from fastapi_authn.oauth.server import Transaction

from .conftest import SECRET

# JWT-based presets


async def test_supabase_with_shared_secret(sign: Callable[..., str]) -> None:
    verifier = SupabaseVerifier(url="https://abc.supabase.co/", jwt_secret=SECRET)
    issuer = "https://abc.supabase.co/auth/v1"
    assert verifier.issuer == issuer
    assert verifier.algorithms == ("HS256",)

    access = await verifier.verify_token(
        sign({"sub": "u1", "aud": "authenticated", "iss": issuer, "role": "authenticated"})
    )
    assert access is not None
    assert access.subject == "u1"
    assert access.client_id is None
    assert await verifier.verify_token(sign({"sub": "u1", "aud": "anon", "iss": issuer})) is None


def test_supabase_with_jwks() -> None:
    verifier = SupabaseVerifier(url="https://abc.supabase.co")
    assert verifier.jwks_url == "https://abc.supabase.co/auth/v1/.well-known/jwks.json"
    assert set(verifier.algorithms) == {"ES256", "RS256"}


async def test_firebase_emulator_tokens(sign: Callable[..., str]) -> None:
    verifier = FirebaseVerifier(project_id="proj", emulator_host="localhost:9099")
    issuer = "https://securetoken.google.com/proj"
    now = int(time.time())

    good = sign(
        {"sub": "uid1", "aud": "proj", "iss": issuer, "auth_time": now - 5, "exp": now + 60}, key="", algorithm="none"
    )
    access = await verifier.verify_token(good)
    assert access is not None
    assert (access.subject, access.resource, access.expires_at) == ("uid1", "proj", now + 60)

    for claims in (
        {"sub": "", "aud": "proj", "iss": issuer},
        {"aud": "proj", "iss": issuer},
        {"sub": "u", "aud": "proj", "iss": issuer, "auth_time": now + 600},
        {"sub": "u", "aud": "other", "iss": issuer},
    ):
        assert await verifier.verify_token(sign(claims, key="", algorithm="none")) is None


def test_firebase_production_uses_google_keys() -> None:
    verifier = FirebaseVerifier(project_id="proj")
    assert verifier.verify_signature
    assert verifier.jwks_url is not None
    assert "securetoken@system.gserviceaccount.com" in verifier.jwks_url

    session = FirebaseSessionVerifier(project_id="proj")
    assert session.issuer == "https://session.firebase.google.com/proj"
    assert session.jwks_url is None


async def test_cognito_access_tokens(sign: Callable[..., str]) -> None:
    verifier = CognitoVerifier(
        region="eu-west-1", user_pool_id="eu-west-1_abc", client_ids=["c1"], verify_signature=False
    )
    issuer = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc"
    assert verifier.jwks_url == issuer + "/.well-known/jwks.json"

    def token(**claims: Any) -> str:
        return sign({"sub": "u", "iss": issuer, **claims}, key="", algorithm="none")

    access = await verifier.verify_token(token(token_use="access", client_id="c1", scope="a b"))
    assert access is not None
    assert (access.client_id, access.scopes) == ("c1", ["a", "b"])
    assert await verifier.verify_token(token(token_use="id", aud="c1")) is None
    assert await verifier.verify_token(token(token_use="access", client_id="c2")) is None
    assert await verifier.verify_token(token(token_use="refresh")) is None


async def test_cognito_id_tokens(sign: Callable[..., str]) -> None:
    verifier = CognitoVerifier(
        region="eu-west-1", user_pool_id="eu-west-1_abc", client_ids=["c1"], token_use="id", verify_signature=False
    )
    assert verifier.audience == ["c1"]
    issuer = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc"
    assert await verifier.verify_token(
        sign({"sub": "u", "iss": issuer, "token_use": "id", "aud": "c1"}, key="", algorithm="none")
    )
    assert (
        await verifier.verify_token(
            sign({"sub": "u", "iss": issuer, "token_use": "id", "aud": "c2"}, key="", algorithm="none")
        )
        is None
    )


async def test_clerk_authorized_parties(sign: Callable[..., str]) -> None:
    verifier = ClerkVerifier(frontend_api="clerk.x.io", authorized_parties=["https://x.io"], verify_signature=False)
    assert verifier.jwks_url == "https://clerk.x.io/.well-known/jwks.json"

    def token(**claims: Any) -> str:
        return sign({"sub": "user_1", "iss": "https://clerk.x.io", "sid": "s", **claims}, key="", algorithm="none")

    assert await verifier.verify_token(token(azp="https://x.io")) is not None
    assert await verifier.verify_token(token()) is not None
    assert await verifier.verify_token(token(azp="https://evil")) is None


@pytest.mark.parametrize(
    ("verifier", "issuer"),
    [
        (Auth0Verifier(domain="t.auth0.com", audience="api"), "https://t.auth0.com/"),
        (OktaVerifier(domain="d.okta.com"), "https://d.okta.com/oauth2/default"),
        (OktaVerifier(domain="d.okta.com", authorization_server=None), "https://d.okta.com"),
        (KeycloakVerifier(server_url="https://sso/", realm="r"), "https://sso/realms/r"),
        (EntraVerifier(tenant="tid", audience="api://x"), "https://login.microsoftonline.com/tid/v2.0"),
    ],
)
def test_oidc_presets_build_their_issuer(verifier: Any, issuer: str) -> None:
    assert verifier.issuer == issuer


def test_entra_multi_tenant_skips_issuer_matching() -> None:
    assert EntraVerifier(tenant="common", audience="x").options == {"issuer": None}
    assert EntraVerifier(tenant="tid", audience="x").options == {}


# GitHub upstream


async def test_github_upstream_identity() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        match request.url.path:
            case "/login/oauth/access_token":
                assert b"code=c0de" in request.content
                assert b"client_id=cid" not in request.content
                return httpx2.Response(200, json={"access_token": "gh", "token_type": "bearer"})
            case "/user":
                assert request.headers["Authorization"] == "Bearer gh"
                return httpx2.Response(
                    200, json={"id": 7, "login": "octo", "name": None, "email": None, "avatar_url": "a"}
                )
            case "/user/emails":
                return httpx2.Response(
                    200,
                    json=[
                        {"email": "x@y", "primary": False, "verified": True},
                        {"email": "o@y", "primary": True, "verified": True},
                    ],
                )
        raise AssertionError(request.url)

    upstream = GitHubUpstream(
        client_id="cid", client_secret="sec", http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
    )
    transaction = Transaction(
        id="t",
        client_id="c",
        redirect_uri="http://a/cb",
        redirect_uri_provided_explicitly=True,
        code_challenge="x",
        scopes=[],
    )  # type: ignore[arg-type]

    request = httpx2.Request("GET", "http://as/oauth/callback?code=c0de&state=t")
    from fastapi import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/oauth/callback",
        "query_string": b"code=c0de&state=t",
        "headers": [],
    }
    identity = await upstream.complete(StarletteRequest(scope), transaction, callback_url="http://as/oauth/callback")
    assert isinstance(identity, Identity)
    assert identity.subject == "7"
    assert identity.claims == {"login": "octo", "name": None, "email": "o@y", "avatar_url": "a"}
    assert identity.upstream_tokens == {"access_token": "gh", "token_type": "bearer"}
    del request


# MCP


def lazy_app(verifier: TokenVerifier, **options: Any) -> TestClient:
    bearer = OAuthBearer(verifier=verifier)
    lazy = LazyBearer(bearer=bearer, **options)
    app = FastAPI()
    add_authn(app)

    @app.post("/mcp")
    async def mcp(token: Annotated[AccessToken | None, Security(lazy)]) -> str | None:
        return token.token if token else None

    return TestClient(app)


def call(client: TestClient, body: Any, token: str | None = None) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/mcp", json=body, headers=headers)


def test_lazy_bearer_protects_tools_on_call_only(verifier_of: Callable[..., TokenVerifier]) -> None:
    client = lazy_app(verifier_of({"t": AccessToken(token="t")}), protected=["secret"], public=["open"])

    assert call(client, {"method": "tools/list"}).json() is None
    assert call(client, {"method": "tools/call", "params": {"name": "open"}}).json() is None
    assert call(client, {"method": "tools/call", "params": {"name": "other"}}).json() is None
    assert call(client, {"method": "tools/call", "params": {"name": "secret"}}).status_code == 401
    assert call(client, {"method": "tools/call", "params": {"name": "secret"}}, token="t").json() == "t"
    assert call(client, "garbage").json() is None


def test_lazy_bearer_protects_everything_by_default(verifier_of: Callable[..., TokenVerifier]) -> None:
    client = lazy_app(verifier_of({}), public=["open"], protected_methods=["resources/read"])
    assert call(client, {"method": "tools/call", "params": {"name": "anything"}}).status_code == 401
    assert call(client, {"method": "tools/call", "params": {"name": "open"}}).status_code == 200
    assert call(client, {"method": "resources/read"}).status_code == 401
    # A token that was sent is checked even where none is needed.
    assert call(client, {"method": "tools/list"}, token="bad").status_code == 401


def test_openai_apps_challenge() -> None:
    app = FastAPI()
    add_authn(app)
    app.include_router(openai_apps_challenge("tok3n"))
    response = TestClient(app).get("/.well-known/openai-apps-challenge")
    assert response.text == "tok3n"


# Missing extras


def test_missing_extra_names_the_install(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi_authn.oauth import backends

    monkeypatch.delitem(sys.modules, "fastapi_authn.oauth.backends.redis", raising=False)
    monkeypatch.setitem(sys.modules, "redis", None)
    monkeypatch.setitem(sys.modules, "redis.asyncio", None)

    with pytest.raises(MissingExtra, match=r"fastapi-authn\[redis\]"):
        _ = backends.RedisStorage

    monkeypatch.delitem(sys.modules, "fastapi_authn.oauth.backends.redis", raising=False)
    importlib.invalidate_caches()


def test_lazy_package_attribute_errors() -> None:
    from fastapi_authn.oauth import verifiers

    with pytest.raises(AttributeError):
        _ = verifiers.Nope  # type: ignore[attr-defined]
