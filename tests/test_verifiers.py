import json
import time
from collections.abc import Callable
from datetime import timedelta

import httpx2
import pytest

from fastapi_authn.exceptions import UserError
from fastapi_authn.oauth.verifiers import IntrospectionVerifier, JWTVerifier, OIDCVerifier

from .conftest import SECRET


def test_jwt_verifier_needs_exactly_one_key_source() -> None:
    with pytest.raises(UserError):
        JWTVerifier()

    with pytest.raises(UserError):
        JWTVerifier(key=SECRET, jwks_url="https://x/jwks")


async def test_jwt_verifier_reads_standard_claims(sign: Callable[..., str]) -> None:
    verifier = JWTVerifier(key=SECRET, algorithms=["HS256"], issuer="https://as", audience="api")
    token = sign(
        {
            "iss": "https://as",
            "aud": ["api", "other"],
            "sub": "u1",
            "client_id": "c1",
            "scope": "a b",
            "exp": time.time() + 60,
        }
    )

    access = await verifier.verify_token(token)
    assert access is not None
    assert access.subject == "u1"
    assert access.client_id == "c1"
    assert access.scopes == ["a", "b"]
    assert access.resource == "api"
    assert access.issuer == "https://as"


async def test_jwt_verifier_reads_scp_and_azp(sign: Callable[..., str]) -> None:
    verifier = JWTVerifier(key=SECRET, algorithms=["HS256"])
    access = await verifier.verify_token(sign({"scp": ["x"], "azp": "app"}))
    assert access is not None
    assert access.scopes == ["x"]
    assert access.client_id == "app"


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://other", "aud": "api"},
        {"iss": "https://as", "aud": "other"},
        {"iss": "https://as", "aud": "api", "exp": 1},
        {"iss": "https://as", "aud": "api", "sub": ""},
    ],
)
async def test_jwt_verifier_rejects(sign: Callable[..., str], claims: dict[str, object]) -> None:
    verifier = JWTVerifier(key=SECRET, algorithms=["HS256"], issuer="https://as", audience="api")
    assert await verifier.verify_token(sign(claims)) is None


async def test_jwt_verifier_rejects_wrong_key_and_garbage(sign: Callable[..., str]) -> None:
    verifier = JWTVerifier(key=SECRET, algorithms=["HS256"])
    assert await verifier.verify_token(sign({"sub": "u"}, key="another-secret-another-secret-123")) is None
    assert await verifier.verify_token("not.a.jwt") is None


async def test_jwt_verifier_without_audience_accepts_any(sign: Callable[..., str]) -> None:
    verifier = JWTVerifier(key=SECRET, algorithms=["HS256"])
    access = await verifier.verify_token(sign({"aud": "whatever"}))
    assert access is not None
    assert access.resource == "whatever"


async def test_unsigned_tokens_only_when_asked(sign: Callable[..., str]) -> None:
    token = sign({"sub": "u"}, key="", algorithm="none")
    assert await JWTVerifier(verify_signature=False).verify_token(token) is not None
    assert await JWTVerifier(key=SECRET, algorithms=["HS256"]).verify_token(token) is None


def mock_client(handler: Callable[[httpx2.Request], httpx2.Response]) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


async def test_oidc_verifier_discovers_the_issuer(sign: Callable[..., str]) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        assert str(request.url) == "https://as/.well-known/openid-configuration"
        return httpx2.Response(
            200,
            json={
                "issuer": "https://as",
                "authorization_endpoint": "https://as/a",
                "token_endpoint": "https://as/t",
                "jwks_uri": "https://as/jwks",
            },
        )

    verifier = OIDCVerifier(
        issuer="https://as",
        audience="api",
        http_client=mock_client(handler),
        # The signing keys are not fetched over the network in tests.
        options={"jwks_url": None, "key": SECRET, "algorithms": ["HS256"]},
    )

    async with verifier.lifespan(None):
        pass

    access = await verifier.verify_token(sign({"iss": "https://as", "aud": "api", "sub": "u"}))
    assert access is not None
    assert access.subject == "u"
    assert await verifier.verify_token(sign({"iss": "https://elsewhere", "aud": "api"})) is None


async def test_introspection_verifier_caches_answers() -> None:
    calls: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request.content.decode())
        assert request.headers["Authorization"].startswith("Basic ")
        token = dict(part.split("=") for part in request.content.decode().split("&"))["token"]
        if token == "live":
            return httpx2.Response(200, json={"active": True, "sub": "u", "client_id": "c", "scope": "a", "aud": "api"})
        return httpx2.Response(200, json={"active": False})

    verifier = IntrospectionVerifier(
        endpoint="https://as/introspect",
        client_id="rs",
        client_secret="pw",
        http_client=mock_client(handler),
        cache_ttl=timedelta(seconds=60),
    )

    live = await verifier.verify_token("live")
    assert live is not None
    assert (live.subject, live.client_id, live.scopes, live.resource) == ("u", "c", ["a"], "api")
    assert await verifier.verify_token("live") is live
    assert await verifier.verify_token("dead") is None
    assert await verifier.verify_token("dead") is None
    assert len(calls) == 2


async def test_introspection_verifier_handles_failures() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if b"token=boom" in request.content:
            return httpx2.Response(500)
        return httpx2.Response(200, content=json.dumps({"active": "maybe"}))

    verifier = IntrospectionVerifier(
        endpoint="https://as/introspect",
        client_id="rs",
        client_secret="pw",
        http_client=mock_client(handler),
        cache_ttl=None,
    )
    assert await verifier.verify_token("boom") is None
    assert await verifier.verify_token("odd") is None
