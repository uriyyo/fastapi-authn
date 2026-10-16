from .github import GitHubUpstream
from .google import GoogleUpstream
from .identity import Authenticate, IdentityUpstream
from .oauth2 import OAuth2Upstream, UpstreamError
from .oidc import OIDCUpstream, ProviderMetadata, discover

__all__ = [
    "Authenticate",
    "GitHubUpstream",
    "GoogleUpstream",
    "IdentityUpstream",
    "OAuth2Upstream",
    "OIDCUpstream",
    "ProviderMetadata",
    "UpstreamError",
    "discover",
]
