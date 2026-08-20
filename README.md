# homelab-auth

`homelab-auth` is a small Go library for adding native OpenID Connect login to self-hosted applications. It uses authorization-code flow with PKCE, verifies ID tokens, and stores a minimal identity in an HMAC-signed, HTTP-only session cookie.

It is intended for applications you control that genuinely need native OIDC. For third-party apps and most homelab dashboards, prefer Authentik's proxy provider with your reverse proxy's `forward_auth` integration. Keep upstream app ports private: identity headers are trustworthy only when your controlled proxy overwrites client-supplied headers.

## Install

```sh
go get github.com/jeeftor/homelab-auth
```

## Use it in an application

Create one confidential OIDC client in your identity provider and register the exact callback URL. Keep the client secret and a separate random session secret in the application's secret store.

```go
auth, err := homelabauth.New(ctx, homelabauth.Config{
    Issuer:        os.Getenv("OIDC_ISSUER"),
    ClientID:      os.Getenv("OIDC_CLIENT_ID"),
    ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
    RedirectURL:   "https://app.example.com/auth/callback",
    SessionSecret: []byte(os.Getenv("SESSION_SECRET")), // at least 32 random bytes
    Logger:        logger,
})
if err != nil {
    return err
}

mux.HandleFunc("GET /auth/login", auth.LoginHandler)
mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
mux.HandleFunc("POST /auth/logout", auth.LogoutHandler)
mux.Handle("GET /settings", auth.RequireGroups([]string{"homelab-admins"}, settingsHandler))
```

`RequireAuthenticated` adds the verified identity to the request context. Use `IdentityFromContext(r.Context())` from a protected handler.

For local HTTP development only, set `InsecureCookies: true` and use a `http://localhost`, `http://127.0.0.1`, or `http://[::1]` callback. Production callbacks must use HTTPS. Production cookies are `Secure`, `HttpOnly`, and `SameSite=Lax` by default; their default `__Host-` name prevents a parent domain from setting them. Sessions default to eight hours and are capped at 24 hours.

## Logging

Pass an application `*slog.Logger` through `Config.Logger`. The library emits structured authentication lifecycle events, such as a session being established, a session ending, or a rejected callback. It deliberately does not log authorization codes, ID/access tokens, cookies, client secrets, session secrets, or state values.

Your app should keep its normal request, audit, upload, download, and domain-event logging. This package only owns identity and authentication events.

## Security notes

- Use HTTPS in production and keep `InsecureCookies` disabled.
- Generate a unique session secret for every application; do not reuse an OIDC client secret as the session secret.
- Grant sensitive routes through an explicit OIDC group, not merely “any authenticated user.”
- The issuer must be reachable when the application starts so discovery metadata and signing keys can be verified.
- The cookie is signed, not encrypted. Keep sensitive claims out of `Identity`.
- Sessions are stateless. Removing a user from an IdP group takes effect when their session expires; rotate the app's session secret to invalidate every active session immediately.
- This package does not add CSRF protection to your application's state-changing endpoints.

## Choosing an Authentik integration

Use an Authentik proxy provider and `forward_auth` for applications that only need a login gate and optional forwarded identity headers. Use this package with an Authentik OAuth/OIDC provider only when your Go application needs native OIDC behavior, such as access tokens for an upstream API. Device Code is for CLIs and Client Credentials is for service-to-service communication; neither belongs in browser session handlers.
