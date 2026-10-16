import time
from collections.abc import Callable
from typing import Annotated

from fastapi import FastAPI, Security
from fastapi.openapi.models import OAuthFlowAuthorizationCode, OAuthFlows
from fastapi.testclient import TestClient

from fastapi_authn.oauth import AccessToken, OAuthBearer, ProtectedResource, TokenVerifier

from .conftest import ISSUER


def app_with(bearer: OAuthBearer) -> TestClient:
    app = FastAPI()

    @app.get("/x")
    async def x(token: Annotated[AccessToken | None, Security(bearer)]) -> str | None:
        return token.token if token else None

    return TestClient(app)


def test_expired_token_is_rejected(verifier_of: Callable[..., TokenVerifier]) -> None:
    verifier = verifier_of({"old": AccessToken(token="old", expires_at=int(time.time()) - 1)})
    response = app_with(OAuthBearer(verifier=verifier)).get("/x", headers={"Authorization": "Bearer old"})
    assert response.status_code == 401
    assert response.json()["detail"]["error_description"] == "Token has expired"


def test_resource_indicator_is_checked(verifier_of: Callable[..., TokenVerifier], resource: ProtectedResource) -> None:
    verifier = verifier_of(
        {
            "ours": AccessToken(token="ours", resource=f"{ISSUER}/api/"),
            "theirs": AccessToken(token="theirs", resource="http://other/api"),
            "none": AccessToken(token="none"),
        }
    )
    client = app_with(OAuthBearer(verifier=verifier, resource=resource))

    # A trailing slash does not matter.
    assert client.get("/x", headers={"Authorization": "Bearer ours"}).json() == "ours"
    assert client.get("/x", headers={"Authorization": "Bearer theirs"}).status_code == 401
    missing = client.get("/x", headers={"Authorization": "Bearer none"})
    assert missing.status_code == 401
    assert "carries no resource indicator" in missing.json()["detail"]["error_description"]

    relaxed = app_with(OAuthBearer(verifier=verifier, resource=resource, validate_resource=False))
    assert relaxed.get("/x", headers={"Authorization": "Bearer theirs"}).json() == "theirs"


def test_auto_error_false_resolves_none(verifier_of: Callable[..., TokenVerifier]) -> None:
    client = app_with(OAuthBearer(verifier=verifier_of({}), auto_error=False))
    assert client.get("/x").json() is None
    assert client.get("/x", headers={"Authorization": "Basic abc"}).json() is None
    assert client.get("/x", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_openapi_scheme_is_http_bearer_or_oauth2(verifier_of: Callable[..., TokenVerifier]) -> None:
    plain = app_with(OAuthBearer(verifier=verifier_of({}), scheme_name="Plain")).get("/openapi.json").json()
    assert plain["components"]["securitySchemes"]["Plain"] == {"type": "http", "scheme": "bearer"}

    flows = OAuthFlows(
        authorizationCode=OAuthFlowAuthorizationCode(
            authorizationUrl="https://as/a", tokenUrl="https://as/t", scopes={}
        )
    )
    oauth = (
        app_with(OAuthBearer(verifier=verifier_of({}), flows=flows, scheme_name="OAuth")).get("/openapi.json").json()
    )
    assert oauth["components"]["securitySchemes"]["OAuth"]["type"] == "oauth2"
