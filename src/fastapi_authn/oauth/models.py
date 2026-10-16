from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal, Protocol, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import (
    AfterValidator,
    AnyHttpUrl,
    AnyUrl,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    model_validator,
)

from .errors import AuthorizeError

__all__ = [
    "DEFAULT_GRANT_TYPES",
    "SCOPES",
    "AccessToken",
    "AuthorizationCode",
    "AuthorizationParams",
    "AuthorizationServerMetadata",
    "BearerTokenType",
    "ClientInformation",
    "ClientMetadata",
    "NonEmpty",
    "OAuthToken",
    "OneOrMany",
    "ProtectedResourceMetadata",
    "RefreshToken",
    "Scopes",
    "Subject",
    "Timestamp",
    "TokenClaims",
    "TokenEndpointAuthMethod",
    "TokenVerifier",
    "construct_redirect_uri",
    "containing",
]

TokenEndpointAuthMethod = Literal["none", "client_secret_post", "client_secret_basic"]

# What a client gets when it registers without saying (RFC 7591 §2).
DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"]

# RFC 8414 issuer comparison is exact, so a URL given without a path must not gain a trailing slash.
URL_CONFIG = ConfigDict(url_preserve_empty_path=True)


# Annotated types


def _split_scopes(value: object) -> object:
    # A scope claim is a space-separated string (RFC 8693 §4.2) or, with some issuers, a list.
    return value.split() if isinstance(value, str) else value


def _listed(value: object) -> object:
    return [value] if isinstance(value, str) else value


def _text(value: object) -> object:
    # Some issuers put a numeric id in a string claim.
    return str(value) if isinstance(value, int | float) and not isinstance(value, bool) else value


def _whole_seconds(value: object) -> object:
    return int(value) if isinstance(value, float) else value


def _titled(value: object) -> object:
    return value.title() if isinstance(value, str) else value


def containing[T](item: T) -> AfterValidator:
    """Requires `item` among a list field's values."""

    def check(items: list[T]) -> list[T]:
        if item not in items:
            raise ValueError(f"must include {item!r}")

        return items

    return AfterValidator(check)


# `"read write"` or `["read", "write"]` to `["read", "write"]`.
type Scopes = Annotated[list[str], BeforeValidator(_split_scopes)]
SCOPES: TypeAdapter[list[str]] = TypeAdapter(Scopes)
# A claim that is one value or a list of them, as `aud`, always read as a list.
type OneOrMany[T] = Annotated[list[T], BeforeValidator(_listed)]
type NonEmpty[T] = Annotated[list[T], Field(min_length=1)]
# A `sub` claim: never empty, and a number is taken as text.
type Subject = Annotated[str, BeforeValidator(_text), Field(min_length=1)]
# A NumericDate claim (RFC 7519 §2): seconds, which some issuers write with a fraction.
type Timestamp = Annotated[int, BeforeValidator(_whole_seconds)]
# RFC 6750 §4 spells it `Bearer`; servers answer `bearer` too.
type BearerTokenType = Annotated[Literal["Bearer"], BeforeValidator(_titled)]


# Tokens


class TokenClaims(BaseModel):
    """The registered claims of a JWT or introspection response (RFC 7519, RFC 7662, RFC 9068); the rest kept."""

    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    iss: str | None = None
    sub: Subject | None = None
    aud: OneOrMany[str] = Field(default_factory=list)
    exp: Timestamp | None = None
    client_id: str | None = None
    azp: str | None = None
    scope: Scopes = Field(default_factory=list)

    def resource(self, accepted: str | Sequence[str] | None = None) -> str | None:
        """The audience the token is taken for: the one in `accepted` when it names several, else its first."""
        accepted = [accepted] if isinstance(accepted, str) else list(accepted or ())

        return next((aud for aud in self.aud if aud in accepted), self.aud[0] if self.aud else None)


class AccessToken(BaseModel):
    """A verified bearer credential: whoever presents it, and what it was issued for.

    Every verifier answers with one, whether the token is opaque, a JWT from an OAuth server or an ID token
    from an identity provider; `claims` carries what the issuer said verbatim.
    """

    token: str
    subject: str | None = None
    # The OAuth client the token was issued to; an identity provider's user token has none.
    client_id: str | None = None
    scopes: list[str] = Field(default_factory=list)
    expires_at: int | None = None
    # RFC 8707 resource indicator, or the audience the token was accepted for.
    resource: str | None = None
    claims: dict[str, Any] | None = None

    @property
    def issuer(self) -> str | None:
        match (self.claims or {}).get("iss"):
            case None:
                return None
            case issuer:
                return str(issuer)


@runtime_checkable
class TokenVerifier(Protocol):
    """Turns a bearer token into an `AccessToken`, or `None` when it does not check out.

    Fill `AccessToken.resource` with what the token was issued for (its RFC 8707 indicator or `aud`), so
    `OAuthBearer` can refuse tokens meant for another resource.
    """

    async def verify_token(self, token: str) -> AccessToken | None: ...


class AuthorizationCode(BaseModel):
    code: str
    client_id: str
    scopes: list[str]
    expires_at: float
    code_challenge: str
    redirect_uri: AnyUrl
    redirect_uri_provided_explicitly: bool
    resource: str | None = None
    subject: str | None = None


class RefreshToken(BaseModel):
    token: str
    client_id: str
    scopes: list[str]
    expires_at: int | None = None
    resource: str | None = None
    subject: str | None = None


class OAuthToken(BaseModel):
    """The token endpoint's answer (RFC 6749 §5.1)."""

    access_token: str
    token_type: BearerTokenType = "Bearer"
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None


# Authorization


class AuthorizationParams(BaseModel):
    """A validated `/authorize` request, as the provider sees it."""

    state: str | None
    scopes: list[str] | None
    code_challenge: str
    redirect_uri: AnyUrl
    redirect_uri_provided_explicitly: bool
    resource: str | None = None


# Clients (RFC 7591)


type EmptyToNone[T] = Annotated[
    T | None,
    BeforeValidator(lambda v: v or None),
]


class ClientMetadata(BaseModel):
    """What a client sends to register (RFC 7591 §2)."""

    model_config = URL_CONFIG

    redirect_uris: NonEmpty[AnyUrl]
    token_endpoint_auth_method: TokenEndpointAuthMethod | None = None
    grant_types: list[str] = Field(default_factory=lambda: list(DEFAULT_GRANT_TYPES))
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    scope: str | None = None
    client_name: str | None = None
    client_uri: EmptyToNone[AnyHttpUrl] | None = None
    logo_uri: EmptyToNone[AnyHttpUrl] | None = None
    contacts: list[str] | None = None
    tos_uri: EmptyToNone[AnyHttpUrl] | None = None
    policy_uri: EmptyToNone[AnyHttpUrl] | None = None
    jwks_uri: EmptyToNone[AnyHttpUrl] | None = None
    jwks: Any | None = None
    software_id: str | None = None
    software_version: str | None = None
    application_type: str | None = None


class ClientInformation(ClientMetadata):
    """The server's record of a registered client: its metadata plus the credentials issued (RFC 7591 §3.2.1)."""

    client_id: str
    client_secret: str | None = None
    client_id_issued_at: int | None = None
    # `0` means the secret never expires.
    client_secret_expires_at: int | None = None

    @model_validator(mode="before")
    @classmethod
    def _placeholders_as_omitted(cls, data: object) -> object:
        if isinstance(data, dict):
            return {key: value for key, value in data.items() if value is not None and value != ""}

        return data

    @property
    def is_confidential(self) -> bool:
        return self.client_secret is not None

    @property
    def allowed_scopes(self) -> list[str]:
        return self.scope.split() if self.scope else []

    def validate_scope(self, requested: str | None) -> list[str] | None:
        if requested is None:
            return None

        scopes = requested.split()

        for scope in scopes:
            if scope not in self.allowed_scopes:
                raise AuthorizeError("invalid_scope", f"Client was not registered with scope {scope}")

        return scopes

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is not None:
            if redirect_uri not in self.redirect_uris:
                raise AuthorizeError("invalid_request", f"Redirect URI '{redirect_uri}' not registered for client")

            return redirect_uri

        if len(self.redirect_uris) == 1:
            return self.redirect_uris[0]

        raise AuthorizeError(
            "invalid_request", "redirect_uri must be specified unless the client has exactly one registered URI"
        )


# Metadata


class AuthorizationServerMetadata(BaseModel):
    """RFC 8414 authorization server metadata."""

    model_config = URL_CONFIG

    issuer: AnyHttpUrl
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    registration_endpoint: AnyHttpUrl | None = None
    revocation_endpoint: AnyHttpUrl | None = None
    introspection_endpoint: AnyHttpUrl | None = None
    jwks_uri: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] = Field(default_factory=lambda: ["code"])
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    revocation_endpoint_auth_methods_supported: list[str] | None = None
    code_challenge_methods_supported: list[str] | None = None
    service_documentation: AnyHttpUrl | None = None
    ui_locales_supported: list[str] | None = None
    op_policy_uri: AnyHttpUrl | None = None
    op_tos_uri: AnyHttpUrl | None = None
    client_id_metadata_document_supported: bool | None = None
    authorization_response_iss_parameter_supported: bool | None = None


class ProtectedResourceMetadata(BaseModel):
    """RFC 9728 protected resource metadata."""

    model_config = URL_CONFIG

    resource: AnyHttpUrl
    authorization_servers: NonEmpty[AnyHttpUrl]
    jwks_uri: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    bearer_methods_supported: list[str] | None = Field(default_factory=lambda: ["header"])
    resource_signing_alg_values_supported: list[str] | None = None
    resource_name: str | None = None
    resource_documentation: AnyHttpUrl | None = None
    resource_policy_uri: AnyHttpUrl | None = None
    resource_tos_uri: AnyHttpUrl | None = None
    tls_client_certificate_bound_access_tokens: bool | None = None
    authorization_details_types_supported: list[str] | None = None
    dpop_signing_alg_values_supported: list[str] | None = None
    dpop_bound_access_tokens_required: bool | None = None


def construct_redirect_uri(base: str, **params: str | None) -> str:
    """`base` with `params` added to its query; `None` values are left out."""
    parsed = urlparse(base)
    query = [*parse_qsl(parsed.query, keep_blank_values=True), *((k, v) for k, v in params.items() if v is not None)]
    return urlunparse(parsed._replace(query=urlencode(query)))
