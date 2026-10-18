from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, nullcontext
from dataclasses import dataclass
from typing import Any, Final

from fastapi import HTTPException, status
from fastapi.openapi.models import HTTPBearer as HTTPBearerModel
from fastapi.openapi.models import OAuth2 as OAuth2Model
from fastapi.openapi.models import OAuthFlows
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import AnyHttpUrl, ValidationError
from starlette.requests import HTTPConnection

from fastapi_authn._lifespan import lifespan_of

from .models import AccessToken, TokenVerifier
from .resource import ProtectedResource
from .types import BearerErrorCode

__all__ = [
    "OAuthBearer",
    "OAuthBearerError",
]

BEARER_SCHEME: Final = "bearer"
WWW_AUTHENTICATE_HEADER: Final = "WWW-Authenticate"


class OAuthBearerError(HTTPException):
    """A 401 whose `WWW-Authenticate` tells the client where to get a token (RFC 6750, RFC 9728)."""

    def __init__(
        self,
        *,
        status_code: int,
        error: BearerErrorCode,
        description: str,
        resource_metadata: AnyHttpUrl | None = None,
    ) -> None:
        parts = [f'error="{error}"', f'error_description="{description}"']

        if resource_metadata is not None:
            parts.append(f'resource_metadata="{resource_metadata}"')

        super().__init__(
            status_code=status_code,
            detail={"error": error, "error_description": description},
            headers={WWW_AUTHENTICATE_HEADER: f"Bearer {', '.join(parts)}"},
        )
        self.error = error
        self.description = description


@dataclass(eq=False, kw_only=True)
class OAuthBearer(SecurityBase):
    """A FastAPI security dependency resolving the request's bearer token to an `AccessToken`.

    Compared by identity, so `Security(bearer)` on a route and `DepFactory[AccessToken, bearer]` in deps
    share one dependency-cache entry.
    """

    verifier: TokenVerifier
    resource: ProtectedResource | None = None
    # Only accept tokens issued for `resource` (RFC 8707): the verifier must fill `AccessToken.resource`, and the
    # client must have sent `resource` when asking for the token; `False` for clients that do not.
    validate_resource: bool = True
    # As FastAPI's: with `False`, a request without credentials resolves to `None` instead of a 401.
    auto_error: bool = True
    scheme_name: str | None = None
    description: str | None = None
    # With the authorization server's flows, Swagger UI can obtain a token.
    flows: OAuthFlows | None = None

    def __post_init__(self) -> None:
        self.scheme_name = self.scheme_name or type(self).__name__
        self.model = (
            OAuth2Model(flows=self.flows, description=self.description)
            if self.flows is not None
            else HTTPBearerModel(description=self.description)
        )

    @asynccontextmanager
    async def lifespan(self, app: Any) -> AsyncGenerator[None]:
        """The verifier's lifespan, when it declares one; run it as part of the app's."""
        lifespan = lifespan_of(self.verifier)

        async with lifespan(app) if lifespan is not None else nullcontext():
            yield

    @property
    def resource_url(self) -> AnyHttpUrl | None:
        return self.resource.metadata.resource if self.resource is not None else None

    @property
    def metadata_url(self) -> AnyHttpUrl | None:
        return self.resource.metadata_url if self.resource is not None else None

    async def __call__(self, request: HTTPConnection) -> AccessToken | None:
        return await self.authenticate(request, auto_error=self.auto_error)

    async def authenticate(self, request: HTTPConnection, *, auto_error: bool) -> AccessToken | None:
        scheme, token = get_authorization_scheme_param(request.headers.get("Authorization"))

        if scheme.lower() != BEARER_SCHEME or not token:
            if not auto_error:
                return None

            raise self.invalid_token("Authentication required")

        access_token = await self.verifier.verify_token(token)

        if access_token is None:
            raise self.invalid_token("Invalid or unknown token")

        if access_token.expires_at is not None and access_token.expires_at < int(time.time()):
            raise self.invalid_token("Token has expired")

        if self.validate_resource and self.resource is not None and not self.issued_for_resource(access_token):
            raise self.invalid_token(self.wrong_resource(access_token))

        return access_token

    def wrong_resource(self, access_token: AccessToken) -> str:
        if access_token.resource is None:
            return f"Token carries no resource indicator; request one for {self.resource_url}"

        return "Token was not issued for this resource"

    def issued_for_resource(self, access_token: AccessToken) -> bool:
        # Compared as URLs, so case and default ports do not matter, a trailing slash aside.
        try:
            token_resource = str(AnyHttpUrl(access_token.resource or ""))
        except ValidationError:
            return False

        return token_resource.removesuffix("/") == str(self.resource_url).removesuffix("/")

    def invalid_token(self, description: str) -> OAuthBearerError:
        return OAuthBearerError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="invalid_token",
            description=description,
            resource_metadata=self.metadata_url,
        )
