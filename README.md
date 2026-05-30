# SecScan - Web Vulnerability Scanner & Security Audit Platform

A full-stack web vulnerability scanner built as a PFA / end-of-year cybersecurity project.

- **Frontend**: Next.js 14 (App Router), TypeScript, TailwindCSS, shadcn/ui, Recharts -> deployed on **Vercel**.
- **Backend API**: FastAPI + SQLAlchemy + PostgreSQL + Redis.
- **Scanner engine**: Celery workers running async Python probes (httpx, dnspython, cryptography).
- **Reports**: PDF generation via ReportLab.
- **Container**: Hardened Docker Compose stack (non-root, read-only FS, dropped caps, no-new-privileges, private network for DB/Redis).
- **Hosting**: Frontend on Vercel (your custom domain); backend stack on any VPS behind Caddy with automatic Let's Encrypt TLS.

> SecScan is a hands-on demonstration of the OWASP Top 10. Only scan systems you own or have written permission to test.

## Architecture

```
+-------------------+     HTTPS + JWT      +----------------------+
|   Next.js (Vercel) |  -----------------> | FastAPI (api.dom)     |
|   - dashboard      |                     |   - auth / scans / RBAC|
|   - new scan       |                     |   - rate limiting      |
|   - PDF download   |                     +-----+-----------+------+
+-------------------+                            |           |
                                                 v           v
                                          +------+----+  +---+-----+
                                          | Postgres  |  |  Redis  |
                                          +-----------+  +----+----+
                                                            |
                                                            v
                                                      +-----+------+
                                                      | Celery     |
                                                      | workers    |
                                                      | (scanner)  |
                                                      +------------+
```

## Capabilities

| Module | Checks |
| --- | --- |
| HTTP Headers | CSP, HSTS, X-Frame, X-CTO, Referrer-Policy, Permissions-Policy, weak CSP detection |
| SSL/TLS | Cert validity, SAN match, weak signatures, TLS 1.0/1.1 support |
| Ports | Top-100 TCP scan with banner grabbing, risky-service flagging |
| Web Vulns | Reflected XSS, SQL injection (error + time-based), open redirect, CORS, sensitive paths |
| Subdomains | crt.sh CT logs + DNS wordlist brute-force |
| Fingerprint | Server/CMS/framework detection via headers + body signatures |

All findings are mapped to **OWASP Top 10 (2021)** with severity scoring and remediation guidance.

## Quick Start (Local)

### Prerequisites

- Docker + Docker Compose v2
- Node.js 20+ (for the frontend)
- Python 3.12 (only if running backend outside Docker)

### 1. Configure environment

```bash
cp .env.example .env
# Generate a strong SECRET_KEY:
openssl rand -hex 32
# Paste into .env, set POSTGRES_PASSWORD, and adjust CORS_ORIGINS
```

### 2. Start the backend stack

```bash
docker compose up -d --build
docker compose ps
curl http://localhost:8000/health
```

### 3. Start the frontend

```bash
cd frontend
cp .env.example .env.local
# .env.local: NEXT_PUBLIC_API_URL=http://localhost:8000
npm install
npm run dev
```

Visit http://localhost:3000.

## Security

See `SECURITY.md` for the complete threat model and mitigations applied. Headlines:

- bcrypt(12) + JWT 15min access / 7d refresh
- Account lockout after 5 failed logins
- slowapi rate limiting (per-IP and per-endpoint)
- SSRF prevention: private IP resolution check before every scan
- Non-root containers, read-only filesystem, dropped caps
- Strict CSP + HSTS + full header suite
- CI runs `pip-audit`, `npm audit`, and Trivy image scan

## Tech Stack

- **Frontend**: Next.js 14, React 18, TypeScript, TailwindCSS, shadcn/ui, TanStack Query, Recharts, react-hook-form, Zod, Zustand
- **Backend**: FastAPI 0.115, SQLAlchemy 2 (asyncio), Pydantic v2, Celery 5
- **Datastore**: PostgreSQL 16, Redis 7
- **Scanner**: httpx, dnspython, cryptography, BeautifulSoup, ReportLab
- **Infra**: Docker, Docker Compose, Caddy, Vercel

## Project Layout

```
sec project/
  backend/                 # FastAPI + Celery + scanner engine
    app/
      api/v1/              # auth, scans, users, reports endpoints
      core/                # config, db, security, rate limiting
      models/              # SQLAlchemy ORM
      schemas/             # Pydantic
      scanner/             # individual modules + engine
      tasks/               # Celery tasks
      reports/             # PDF generator
    Dockerfile
    requirements.txt
  frontend/                # Next.js app (deploy to Vercel)
    src/
      app/                 # App Router pages
      components/ui/       # shadcn-style components
      lib/                 # api client, utils
      stores/              # zustand stores
      types/
    next.config.js
    vercel.json
  deploy/
    Caddyfile              # Reverse proxy for prod
  .github/workflows/ci.yml
  docker-compose.yml       # Production stack
  docker-compose.dev.yml   # Dev override (hot reload)
  .env.example
  SECURITY.md
```

## License

MIT (or your preferred license)
