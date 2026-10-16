from __future__ import annotations

import re
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Final

import anyio.to_thread
from pydantic import BaseModel, TypeAdapter, ValidationError

from fastapi_authn.exceptions import MissingExtra
from fastapi_authn.oauth.models import AccessToken, Subject
from fastapi_authn.oauth.verifiers.jwt import JWTVerifier

try:
    from cryptography import x509
except ImportError as e:
    raise MissingExtra("firebase", "FirebaseVerifier") from e

__all__ = [
    "FirebaseSessionVerifier",
    "FirebaseVerifier",
    "X509Certificates",
]

ID_TOKEN_ISSUER: Final = "https://securetoken.google.com/{project_id}"
ID_TOKEN_JWKS_URL: Final = "https://www.googleapis.com/service_account/v1/jwk/securetoken@system.gserviceaccount.com"
SESSION_COOKIE_ISSUER: Final = "https://session.firebase.google.com/{project_id}"
SESSION_COOKIE_CERTIFICATES_URL: Final = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys"
MAX_AGE: Final = re.compile(r"max-age=(\d+)")
CERTIFICATES: TypeAdapter[dict[str, str]] = TypeAdapter(dict[str, str])


class FirebaseClaims(BaseModel):
    """What Firebase guarantees beyond the registered claims; `sub` is the user's uid and never empty."""

    sub: Subject
    exp: int | None = None
    auth_time: float | None = None


@dataclass(kw_only=True)
class FirebaseVerifier(JWTVerifier):
    """Firebase ID tokens, as the client SDK's `getIdToken()` hands them out.

    With `emulator_host`, the Auth emulator's unsigned tokens are accepted; never in production.
    """

    project_id: str
    emulator_host: str | None = None

    jwks_url: str | None = field(init=False, default=None)
    issuer: str | None = field(init=False, default=None)
    audience: str | None = field(init=False, default=None)  # type: ignore[assignment]
    client_id_claims: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        self.issuer = ID_TOKEN_ISSUER.format(project_id=self.project_id)
        self.audience = self.project_id

        if self.emulator_host is not None:
            self.verify_signature = False
        else:
            self.jwks_url = ID_TOKEN_JWKS_URL

        super().__post_init__()

    def access_token(self, token: str, claims: dict[str, Any]) -> AccessToken | None:
        # Firebase's own checks beyond the signature, issuer and audience.
        try:
            firebase = FirebaseClaims.model_validate(claims)
        except ValidationError:
            return None

        if firebase.auth_time is not None and firebase.auth_time > time.time() + self.leeway:
            return None

        return AccessToken(
            token=token, subject=firebase.sub, expires_at=firebase.exp, resource=self.project_id, claims=claims
        )


@dataclass
class X509Certificates:
    """Google's `{kid: PEM certificate}` key listing, cached for as long as its `Cache-Control` allows."""

    url: str
    _keys: dict[str, Any] = field(init=False, default_factory=dict, repr=False)
    _valid_until: float = field(init=False, default=0, repr=False)

    def fetch(self) -> None:
        with urllib.request.urlopen(self.url, timeout=15) as response:  # noqa: S310
            certificates = CERTIFICATES.validate_json(response.read())
            cache_control = response.headers.get("Cache-Control", "")

        self._keys = {
            kid: x509.load_pem_x509_certificate(pem.encode()).public_key() for kid, pem in certificates.items()
        }
        self._valid_until = time.time() + int(match.group(1)) if (match := MAX_AGE.search(cache_control)) else 0

    def key(self, kid: str) -> Any:
        if kid not in self._keys or self._valid_until < time.time():
            self.fetch()

        if (key := self._keys.get(kid)) is None:
            raise KeyError(f"No certificate for key id {kid!r}")

        return key


@dataclass(kw_only=True)
class FirebaseSessionVerifier(FirebaseVerifier):
    """Firebase session cookies, as the Admin SDK's `createSessionCookie()` mints them; different keys and issuer."""

    certificates: X509Certificates = field(default_factory=lambda: X509Certificates(SESSION_COOKIE_CERTIFICATES_URL))

    def __post_init__(self) -> None:
        super().__post_init__()
        self.issuer = SESSION_COOKIE_ISSUER.format(project_id=self.project_id)
        self.jwks_url = None

    async def signing_key(self, token: str) -> Any:
        if not self.verify_signature:
            return ""

        import jwt

        kid = jwt.get_unverified_header(token).get("kid", "")

        try:
            return await anyio.to_thread.run_sync(self.certificates.key, kid)
        except KeyError as e:
            raise jwt.InvalidKeyError(str(e)) from e
