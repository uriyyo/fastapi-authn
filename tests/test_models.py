import pytest
from pydantic import ValidationError

from fastapi_authn.oauth import ClientInformation, OAuthToken
from fastapi_authn.oauth.errors import AuthorizeError
from fastapi_authn.oauth.models import (
    SCOPES,
    AccessToken,
    ClientMetadata,
    ProtectedResourceMetadata,
    TokenClaims,
    construct_redirect_uri,
)


def test_scopes_accept_a_string_or_a_list() -> None:
    assert SCOPES.validate_python("read write") == ["read", "write"]
    assert SCOPES.validate_python(["read", "write"]) == ["read", "write"]
    assert SCOPES.validate_python("") == []


def test_token_claims_normalize_registered_claims() -> None:
    claims = TokenClaims.model_validate({"sub": 42, "aud": "api", "scope": "a b", "exp": 10, "custom": 1})
    assert claims.sub == "42"
    assert claims.aud == ["api"]
    assert claims.scope == ["a", "b"]
    assert claims.model_extra == {"custom": 1}


def test_token_claims_reject_an_empty_subject() -> None:
    with pytest.raises(ValidationError):
        TokenClaims.model_validate({"sub": ""})


def test_token_claims_resource_picks_the_accepted_audience() -> None:
    claims = TokenClaims.model_validate({"aud": ["x", "y"]})
    assert claims.resource("y") == "y"
    assert claims.resource(["z", "x"]) == "x"
    assert claims.resource() == "x"
    assert claims.resource("nope") == "x"
    assert TokenClaims().resource() is None


def test_access_token_issuer_comes_from_claims() -> None:
    assert AccessToken(token="t", claims={"iss": "https://as"}).issuer == "https://as"
    assert AccessToken(token="t").issuer is None


def test_oauth_token_normalizes_token_type() -> None:
    assert OAuthToken(access_token="t", token_type="bearer").token_type == "Bearer"  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        OAuthToken(access_token="t", token_type="mac")  # type: ignore[arg-type]


def test_client_metadata_treats_empty_urls_as_absent() -> None:
    metadata = ClientMetadata.model_validate({"redirect_uris": ["http://a/b"], "client_uri": "", "logo_uri": None})
    assert metadata.client_uri is None
    assert metadata.logo_uri is None

    with pytest.raises(ValidationError):
        ClientMetadata.model_validate({"redirect_uris": []})


def test_client_information_reads_placeholders_as_defaults() -> None:
    client = ClientInformation.model_validate(
        {"client_id": "c", "redirect_uris": ["http://a/b"], "grant_types": None, "scope": ""}
    )
    assert client.grant_types == ["authorization_code", "refresh_token"]
    assert client.scope is None
    assert not client.is_confidential


def test_client_information_validates_scope_and_redirect_uri() -> None:
    client = ClientInformation.model_validate(
        {"client_id": "c", "redirect_uris": ["http://a/b", "http://a/c"], "scope": "read"}
    )
    assert client.validate_scope(None) is None
    assert client.validate_scope("read") == ["read"]

    with pytest.raises(AuthorizeError) as refused:
        client.validate_scope("write")
    assert refused.value.error == "invalid_scope"

    with pytest.raises(AuthorizeError):
        client.validate_redirect_uri(None)

    single = ClientInformation.model_validate({"client_id": "c", "redirect_uris": ["http://a/b"]})
    assert str(single.validate_redirect_uri(None)) == "http://a/b"


def test_protected_resource_metadata_needs_an_authorization_server() -> None:
    with pytest.raises(ValidationError):
        ProtectedResourceMetadata.model_validate({"resource": "https://r", "authorization_servers": []})


def test_construct_redirect_uri_keeps_existing_query() -> None:
    assert construct_redirect_uri("http://a/cb?x=1", code="c", state=None) == "http://a/cb?x=1&code=c"
