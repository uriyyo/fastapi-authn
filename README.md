# fastapi-authn

Authentication for FastAPI: security schemes that are plain dependencies, chains that try several of them,
a Starlette `AuthenticationMiddleware` backend, and an OAuth 2.1 authorization server with pluggable storage,
verifiers and upstream identity providers.

```sh
pip install fastapi-authn            # schemes, chain, middleware backend
pip install "fastapi-authn[oauth]"   # plus the authorization server, JWT and OIDC verifiers
```

Authorization lives in [fastapi-has-permissions](https://pypi.org/project/fastapi-has-permissions/); this
package only answers who is calling.
