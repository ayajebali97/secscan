# Security Posture

SecScan is itself a security tool, so the application is hardened end-to-end.

## Threat Model

| Concern | Mitigation |
| --- | --- |
| SSRF via scan target | `app/scanner/target_validator.py` blocks private/loopback/link-local IPs, blocked TLDs and resolves all hostnames before scanning |
| Credential brute-force | Per-IP rate limiting on `/auth/login` and `/auth/register` (slowapi) + per-user account lockout after 5 failures |
| Token replay | Short-lived access tokens (15 min) + sliding refresh tokens, JWT type claim enforced on decode |
| Session hijack via XSS | Strict CSP both on backend and frontend, tokens in `sessionStorage` (not localStorage), httpOnly response cookies optional |
| Clickjacking | `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| MITM | HSTS preload, TLS terminated by reverse proxy (Caddy), HTTPS-only cookies |
| Mass-assignment | Pydantic schemas constrain inputs server-side |
| Container escape | Non-root user, `no-new-privileges`, dropped capabilities, read-only filesystem |
| Supply chain | `pip-audit` + `npm audit` + Trivy in CI |
| Sensitive disclosure | `Server` / `X-Powered-By` headers stripped, stack traces hidden in production |

## Authentication

- Passwords: bcrypt (12 rounds) + minimum 12 chars and 3 character classes
- Account lockout: 5 failed attempts -> 15 min lockout
- JWT: HS256 with secret >= 32 chars (validated at startup)
- Refresh: rotate refresh token on each refresh

## RBAC

Three roles: `admin`, `analyst`, `viewer`. New registrations default to `analyst`. Admin-only endpoints use the `require_role(UserRole.ADMIN)` dependency.

## Rate Limiting

- Global default: 60 req/min per IP
- Auth endpoints: 5 req/min per IP
- Scan creation: 10 req/min per authenticated session
- Backed by Redis fixed-window strategy

## Headers

The FastAPI app emits:

- `Strict-Transport-Security`
- `Content-Security-Policy` (default-src 'none' for API responses)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy: same-origin`

The Next.js app emits a frontend-appropriate CSP that only allows the configured backend origin in `connect-src`.

## Container Hardening

The backend image:

- Runs as UID 1000 (no root)
- Read-only filesystem with a small `/tmp` tmpfs
- All Linux capabilities dropped
- `no-new-privileges` security option
- Healthcheck via `/health`

Postgres and Redis containers run in a Docker-internal network only.

## Reporting Vulnerabilities

If you discover a security issue in SecScan, please open a private issue on the project tracker or email the maintainer. Do not include sensitive scan output in public issues.
