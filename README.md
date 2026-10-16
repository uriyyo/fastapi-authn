# fastapi-authn

Authentication for FastAPI: security schemes that are plain dependencies, chains that try several of them,
a Starlette `AuthenticationMiddleware` backend, an OAuth 2.1 authorization server with pluggable storage,
verifiers and upstream identity providers, and ready-made verifiers for popular identity products.

```sh
pip install fastapi-authn                  # schemes, chain, middleware backend, authorization server
pip install "fastapi-authn[jwt]"           # JWT verifier
pip install "fastapi-authn[oidc]"          # OpenID Connect verifier and upstream
pip install "fastapi-authn[firebase]"      # fastapi_authn.ext.firebase, likewise auth0, clerk, cognito, ...
pip install "fastapi-authn[all]"           # everything
```

`fastapi_authn.oauth` is the generic OAuth machinery. `fastapi_authn.ext` holds one module per vendor or
protocol (`firebase`, `supabase`, `auth0`, `okta`, `keycloak`, `entra`, `cognito`, `clerk`, `google`,
`github`, `mcp`), each
needing only its own extra.

This package only answers who is calling; what the caller may do is the application's to decide.
