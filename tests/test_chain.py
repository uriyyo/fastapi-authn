from typing import Annotated, Any

import pytest
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
    OAuth2AuthorizationCodeBearer,
)
from fastapi.testclient import TestClient

from fastapi_authn import AuthChain

from .conftest import User


@pytest.fixture
def auth() -> AuthChain[User]:
    auth = AuthChain[User]()

    @auth.scheme(HTTPBearer())
    async def by_token(credentials: HTTPAuthorizationCredentials) -> User | None:
        return User(credentials.credentials) if credentials.credentials != "bad" else None

    @auth.scheme(APIKeyHeader(name="X-API-Key"))
    async def by_key(key: str, request: Request) -> User | None:
        return User(f"key:{key}:{request.url.path}")

    @auth.scheme(HTTPBasic())
    async def by_basic(credentials: HTTPBasicCredentials) -> User | None:
        return User(credentials.username) if credentials.password == "pw" else None

    return auth


@pytest.fixture
def app(auth: AuthChain[User]) -> FastAPI:
    app = FastAPI()

    @app.get("/me")
    async def me(user: Annotated[User, Security(auth)]) -> User:
        return user

    @app.get("/scoped")
    async def scoped(user: Annotated[User, Security(auth, scopes=["read"])]) -> User:
        return user

    @app.get("/maybe")
    async def maybe(user: Annotated[User | None, Security(auth.optional)]) -> User | None:
        return user

    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_each_scheme_resolves_its_credential(client: TestClient) -> None:
    assert client.get("/me", headers={"Authorization": "Bearer t1"}).json() == {"name": "t1"}
    assert client.get("/me", headers={"X-API-Key": "k"}).json() == {"name": "key:k:/me"}
    assert client.get("/me", auth=("alice", "pw")).json() == {"name": "alice"}


def test_first_registered_wins(client: TestClient) -> None:
    response = client.get("/me", headers={"Authorization": "Bearer t1", "X-API-Key": "k"})
    assert response.json() == {"name": "t1"}


def test_authenticators_run_lazily_and_stop_at_the_first_actor() -> None:
    calls: list[str] = []
    auth = AuthChain[User]()

    @auth.scheme(HTTPBearer())
    async def by_token(credentials: HTTPAuthorizationCredentials) -> User | None:
        calls.append("token")
        return User(credentials.credentials)

    @auth.authenticator
    async def by_query(request: Request) -> User | None:
        calls.append("query")
        name = request.query_params.get("as")
        return User(name) if name else None

    @auth.scheme(APIKeyHeader(name="X-API-Key"))
    async def by_key(key: str) -> User | None:
        calls.append("key")
        return User(key)

    app = FastAPI()

    @app.get("/me")
    async def me(user: Annotated[User | None, Security(auth.optional)]) -> User | None:
        return user

    client = TestClient(app)

    # A scheme whose credential was not sent is not even called; the first actor ends the chain.
    assert client.get("/me", headers={"X-API-Key": "k"}).json() == {"name": "k"}
    assert calls == ["query", "key"]

    calls.clear()
    assert client.get("/me", headers={"Authorization": "Bearer t", "X-API-Key": "k"}).json() == {"name": "t"}
    assert calls == ["token"]

    calls.clear()
    assert client.get("/me").json() is None
    assert calls == ["query"]


def test_missing_credential_is_401_naming_http_schemes(client: TestClient, auth: AuthChain[User]) -> None:
    response = client.get("/me")
    assert response.status_code == 401
    # The API key scheme has no HTTP challenge to add.
    assert response.headers["www-authenticate"] == "Bearer, Basic"
    assert auth.www_authenticate == "Bearer, Basic"


def test_refused_credential_is_401(client: TestClient) -> None:
    assert client.get("/me", headers={"Authorization": "Bearer bad"}).status_code == 401
    assert client.get("/me", auth=("alice", "wrong")).status_code == 401


def test_optional_chain_resolves_none_without_credential(client: TestClient) -> None:
    assert client.get("/maybe").json() is None
    assert client.get("/maybe", headers={"X-API-Key": "k"}).json() == {"name": "key:k:/maybe"}


def test_a_verify_function_answers_none_to_pass_and_raises_to_refuse() -> None:
    auth = AuthChain[User]()

    @auth.scheme(HTTPBearer())
    async def by_token(credentials: HTTPAuthorizationCredentials) -> User | None:
        if credentials.credentials == "revoked":
            raise HTTPException(401, "Token revoked")

        return User(credentials.credentials) if credentials.credentials != "unknown" else None

    @auth.scheme(APIKeyHeader(name="X-API-Key"))
    async def by_key(key: str) -> User | None:
        return User(key)

    app = FastAPI()

    @app.get("/maybe")
    async def maybe(user: Annotated[User | None, Security(auth.optional)]) -> User | None:
        return user

    client = TestClient(app)
    # `None` hands over to the next authenticator; the optional chain then resolves to nothing.
    assert client.get("/maybe", headers={"Authorization": "Bearer unknown", "X-API-Key": "k"}).json() == {"name": "k"}
    assert client.get("/maybe", headers={"Authorization": "Bearer unknown"}).json() is None
    # An error ends the chain, optional or not.
    assert client.get("/maybe", headers={"Authorization": "Bearer revoked"}).status_code == 401


def test_optional_is_shared_and_follows_registration(auth: AuthChain[User]) -> None:
    optional = auth.optional
    assert optional is auth.optional
    assert optional.optional is optional
    assert optional.auto_error is False

    @auth.authenticator
    async def later() -> User | None:
        return None

    assert later in optional.authenticators
    assert list(optional.__signature__.parameters) == list(auth.__signature__.parameters)


def test_openapi_lists_every_scheme_as_an_alternative(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    assert list(spec["components"]["securitySchemes"]) == ["HTTPBearer", "APIKeyHeader", "HTTPBasic"]
    assert spec["paths"]["/me"]["get"]["security"] == [{"HTTPBearer": []}, {"APIKeyHeader": []}, {"HTTPBasic": []}]
    assert spec["paths"]["/scoped"]["get"]["security"] == [
        {"HTTPBearer": ["read"]},
        {"APIKeyHeader": ["read"]},
        {"HTTPBasic": ["read"]},
    ]


def test_scheme_leaves_the_given_scheme_untouched() -> None:
    scheme = HTTPBearer()
    auth = AuthChain[User]()

    @auth.scheme(scheme)
    async def by_token(credentials: HTTPAuthorizationCredentials) -> User | None:
        return User(credentials.credentials)

    assert scheme.auto_error is True
    assert auth.schemes[0] is not scheme
    assert auth.schemes[0].auto_error is False  # type: ignore[attr-defined]


def test_oauth2_scheme_challenges_with_bearer() -> None:
    auth = AuthChain[User]()
    scheme = OAuth2AuthorizationCodeBearer(authorizationUrl="https://as/authorize", tokenUrl="https://as/token")

    @auth.scheme(scheme)
    async def by_token(token: str) -> User | None:
        return User(token)

    assert auth.www_authenticate == "Bearer"


def test_default_challenge_without_schemes_is_bearer() -> None:
    auth = AuthChain[User]()

    @auth.authenticator
    async def never(request: Request) -> User | None:
        return None

    assert auth.www_authenticate == "Bearer"


def test_custom_challenge() -> None:
    auth = AuthChain[User](
        challenge=lambda description: HTTPException(401, description, headers={"WWW-Authenticate": 'Bearer realm="x"'})
    )
    app = FastAPI()

    @app.get("/x")
    async def x(user: Annotated[User, Security(auth)]) -> User:
        return user

    response = TestClient(app).get("/x")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="x"'
    assert response.json() == {"detail": "Authentication required"}


def test_plain_authenticator_with_own_dependencies() -> None:
    auth = AuthChain[User]()

    @auth.authenticator
    async def by_query(request: Request) -> User | None:
        name = request.query_params.get("as")
        return User(name) if name else None

    app = FastAPI()

    @app.get("/me")
    async def me(user: Annotated[User, Security(auth)]) -> User:
        return user

    client = TestClient(app)
    assert client.get("/me", params={"as": "q"}).json() == {"name": "q"}
    assert client.get("/me").status_code == 401


def test_dependency_overrides_apply_to_authenticators(app: FastAPI, auth: AuthChain[User]) -> None:
    by_key = auth.authenticators[1]

    async def override(**kwargs: Any) -> User:
        return User("overridden")

    override.__signature__ = by_key.__signature__  # type: ignore[attr-defined]
    app.dependency_overrides[by_key] = override

    assert TestClient(app).get("/me", headers={"X-API-Key": "k"}).json() == {"name": "overridden"}


def test_unparametrized_chain_works() -> None:
    auth = AuthChain()

    @auth.authenticator
    async def anything(request: Request) -> dict[str, str] | None:
        return {"k": "v"}

    app = FastAPI()

    @app.get("/x")
    async def x(actor: Annotated[Any, Security(auth)]) -> Any:
        return actor

    assert TestClient(app).get("/x").json() == {"k": "v"}
