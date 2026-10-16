from typing import Annotated

import pytest
from fastapi import FastAPI, Request, Security, WebSocket
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.testclient import TestClient
from starlette.authentication import requires
from starlette.middleware.authentication import AuthenticationMiddleware

from fastapi_authn import AUTHENTICATED, ActorUser, AuthChain, ChainBackend

from .conftest import User


@pytest.fixture
def app() -> FastAPI:
    auth = AuthChain[User]()
    calls: list[str] = []

    @auth.scheme(HTTPBearer())
    async def by_token(credentials: HTTPAuthorizationCredentials) -> User | None:
        calls.append(credentials.credentials)
        return User(credentials.credentials) if credentials.credentials != "bad" else None

    app = FastAPI()
    app.state.calls = calls
    app.add_middleware(AuthenticationMiddleware, backend=ChainBackend(auth, display_name=lambda u: u.name.upper()))

    @app.get("/me")
    async def me(user: Annotated[User, Security(auth)]) -> User:
        return user

    @app.get("/starlette")
    @requires(AUTHENTICATED)
    async def starlette(request: Request) -> dict[str, object]:
        return {"display": request.user.display_name, "scopes": list(request.auth.scopes)}

    @app.get("/anonymous")
    async def anonymous(request: Request) -> dict[str, bool]:
        return {"authenticated": request.user.is_authenticated}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_json({"user": websocket.user.display_name if websocket.user.is_authenticated else None})
        await websocket.close()

    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_middleware_fills_request_user(client: TestClient) -> None:
    response = client.get("/starlette", headers={"Authorization": "Bearer t1"})
    assert response.json() == {"display": "T1", "scopes": [AUTHENTICATED]}


def test_requires_decorator_rejects_anonymous(client: TestClient) -> None:
    assert client.get("/starlette").status_code == 403
    assert client.get("/anonymous").json() == {"authenticated": False}


def test_bad_credential_stays_anonymous_for_middleware_but_401_on_route(client: TestClient) -> None:
    assert client.get("/anonymous", headers={"Authorization": "Bearer bad"}).json() == {"authenticated": False}
    assert client.get("/me", headers={"Authorization": "Bearer bad"}).status_code == 401


def test_route_reuses_the_actor_the_middleware_found(client: TestClient, app: FastAPI) -> None:
    assert client.get("/me", headers={"Authorization": "Bearer once"}).json() == {"name": "once"}
    assert app.state.calls.count("once") == 1


def test_websocket_handshake_is_authenticated(client: TestClient) -> None:
    with client.websocket_connect("/ws", headers={"Authorization": "Bearer w"}) as websocket:
        assert websocket.receive_json() == {"user": "W"}

    with client.websocket_connect("/ws") as websocket:
        assert websocket.receive_json() == {"user": None}


def test_actor_user_defaults_to_str() -> None:
    user = ActorUser(User("a"))
    assert user.is_authenticated
    assert user.display_name == "User(name='a')"
    assert user.identity == user.display_name
    assert ActorUser(User("a"), display_name="A").display_name == "A"
