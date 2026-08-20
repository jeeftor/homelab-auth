# Changelog

## 0.1.0 - 2026-08-20

### Added

- Native OpenID Connect browser login using Authorization Code with PKCE,
  verified ID tokens, and group-based route middleware.
- Authentik deployment guidance that reserves native OIDC for first-party Go
  applications and recommends forward authentication for most dashboards.

### Security

- Require HTTPS callbacks in production and limit insecure development cookies
  to localhost.
- Use host-only production cookie defaults, cap session lifetimes, and avoid
  logging user subjects.
- Add automated race, static-analysis, and Go vulnerability checks.
