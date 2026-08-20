# Security Policy

## Supported versions

Security fixes are made on the latest commit on `master`. Consumers must build
and run with a currently supported, patched Go release.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability reporting for this repository. If private reporting is not
available, contact the repository maintainer through their GitHub profile and
include a minimal reproduction, impact, and any proposed mitigation.

## Deployment boundary

This library protects only the Go routes to which its middleware is applied.
Applications remain responsible for HTTPS termination, trusted-proxy boundaries,
CSRF protection for state-changing requests, secret storage, authorization
policy, dependency updates, and secure exposure of their listening port.
