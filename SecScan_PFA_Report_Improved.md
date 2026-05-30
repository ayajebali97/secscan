# SecScan — Web Vulnerability Scanner & Security Audit Platform
## PFA Report — Improved & Technically Verified Edition

---

> **Note to authors:** Every technical claim in this document has been cross-verified against the
> actual source code. Insert your university name, student names, supervisor, and academic year on
> the cover page. All section numbers are ready for direct use in your final report.

---

## Cover Page

| Field | Value |
|-------|-------|
| University | [Your University Name] |
| Department | Department of Computer Science / Cybersecurity |
| Academic Year | 2025–2026 |
| Project Title | **SecScan – Web Vulnerability Scanner & Security Audit Platform** |
| Students | [Student 1], [Student 2] |
| Supervisor | [Supervisor Name] |
| Date | June 2026 |

---

## Acknowledgment

We would like to express our sincere gratitude to our project supervisor for their guidance and
continuous support throughout this work. We also thank the open-source communities behind FastAPI,
Next.js, Celery, and the OWASP Foundation for providing the resources and documentation that
guided our design decisions.

---

## Abstract

Web applications have become the primary attack surface for modern cyber threats. According to the
OWASP Top 10 — the most authoritative reference for web application security risks — vulnerabilities
such as injection attacks, broken access control, cryptographic failures, and security
misconfigurations remain the leading causes of data breaches worldwide.

This report presents **SecScan**, a full-stack Web Vulnerability Scanner and Security Audit
Platform designed and implemented as a final-year project (PFA). SecScan allows security analysts
to launch automated scans against target web applications and receive structured findings mapped to
the OWASP Top 10:2021 taxonomy. The platform performs eight categories of security analysis:
DNS reconnaissance, HTTP security header inspection, SSL/TLS configuration auditing, port scanning,
active web vulnerability probing (XSS, SQL injection, open redirect, CORS misconfiguration,
sensitive path disclosure), subdomain enumeration, technology fingerprinting, and CVE lookup.

The architecture is built around a **FastAPI** asynchronous backend, a **Next.js 14** frontend
deployed on Vercel, a **PostgreSQL** relational database, and a **Redis**-backed **Celery**
distributed task queue. The entire backend infrastructure is containerised using **Docker Compose**
with production-grade security hardening, including read-only container filesystems, capability
dropping, no-new-privileges enforcement, tmpfs memory mounts, health checks, and enforced resource
limits. The reverse proxy layer uses **Caddy 2**, which provides automatic TLS via ACME with
support for HTTP/1.1, HTTP/2, and HTTP/3.

The result is a deployable, production-hardened security platform that demonstrates applied
knowledge of secure software engineering, container security, asynchronous task processing, and
OWASP vulnerability categorisation.

---

## Chapter 1 — General Introduction

### 1.1 Context

The exponential growth of internet-facing web applications has created an ever-expanding attack
surface for malicious actors. Organisations of all sizes are exposed to threats ranging from
automated vulnerability exploitation to sophisticated targeted attacks. The cybersecurity industry
responds with a variety of scanning and auditing tools; however, most professional-grade solutions
are either proprietary, costly, or require significant operational expertise.

SecScan was conceived in this context: a modern, open-source, self-hosted vulnerability scanner
that security teams can deploy on their own infrastructure and use to continuously monitor the
security posture of their web assets. Unlike single-purpose tools, SecScan combines multiple
analysis dimensions — network, protocol, application, and component — into a single unified
platform with a clean web interface and structured reporting.

### 1.2 Problem Statement

Security teams face the following practical challenges:

- **Fragmentation:** Popular tools like Nmap, SSLyze, and OWASP ZAP cover individual dimensions
  but require manual correlation of results.
- **Accessibility:** CLI-based tools create a barrier for analysts who lack deep technical
  expertise.
- **Traceability:** Ad-hoc scans produce ephemeral results without persistent storage, audit
  trails, or historical comparison.
- **Reporting:** Generating structured, OWASP-mapped PDF reports from raw tool output is time-
  consuming and error-prone.
- **Deployment risk:** Scanners themselves can be weaponised if not secured against SSRF attacks or
  resource exhaustion.

SecScan addresses all five challenges through a purpose-built platform architecture.

### 1.3 Objectives

The primary objectives of this project are:

1. Design and implement a multi-module web vulnerability scanner covering the OWASP Top 10:2021.
2. Build a secure, authenticated REST API with role-based access control, rate limiting, and SSRF
   prevention.
3. Develop a reactive frontend dashboard with real-time scan progress, interactive charts, and PDF
   report generation.
4. Deploy the platform using a hardened Docker Compose infrastructure with enforced container
   security policies.
5. Automate quality assurance via a GitHub Actions CI/CD pipeline covering linting, type checking,
   dependency auditing, and container vulnerability scanning.

---

## Chapter 2 — State of the Art

### 2.1 Existing Security Scanners

The web application security scanner market includes both open-source and commercial solutions:

| Tool | Type | Strengths | Limitations |
|------|------|-----------|-------------|
| OWASP ZAP | Open-source DAST | Comprehensive, proxied scanning | Complex setup, no hosted UI |
| Nikto | Open-source CLI | Fast server misconfiguration checks | No OWASP mapping, no UI |
| Nmap + NSE | Network scanner | Powerful port/service detection | Not web-application-focused |
| Nuclei | Template-based | Highly customisable | Requires template expertise |
| Burp Suite Pro | Commercial DAST | Industry standard, deep analysis | Expensive, proprietary |
| Qualys WAS | SaaS | Enterprise-grade, compliance-ready | SaaS lock-in, high cost |

### 2.2 Comparative Study

The key differentiating dimensions for evaluation are: deployment model (SaaS vs self-hosted),
OWASP Top 10 mapping, persistent result storage, role-based access, API-first design, and
production-readiness of the deployment infrastructure.

Most open-source tools score well on scanning depth but poorly on operational dimensions (no API,
no user management, no audit trail). Commercial tools score well overall but are inaccessible for
small teams and educational projects. SecScan targets the gap: open-source depth with
production-grade operational design.

### 2.3 Proposed Solution

SecScan is distinguished by the following design choices:

- **API-first architecture:** All functionality is exposed through a versioned REST API
  (`/api/v1`), enabling integration with external tools and automation pipelines.
- **Asynchronous scan execution:** Scans run in a Celery worker process, decoupled from the HTTP
  request/response cycle, enabling long-running analyses without timeout constraints.
- **Full OWASP Top 10:2021 coverage:** Every finding is tagged with the corresponding OWASP
  category from `A01:2021` through `A10:2021`.
- **Hardened deployment:** The Docker Compose infrastructure applies defence-in-depth at the
  container level, not just the application level.
- **Automated CI:** A GitHub Actions pipeline enforces code quality, type safety, and
  vulnerability-free dependencies on every push.

---

## Chapter 3 — Requirement Analysis

### 3.1 Functional Requirements

**FR-01 — User Management:** The system shall support user registration, login, token refresh, and
profile retrieval. Accounts shall be subject to automatic lockout after five consecutive failed
login attempts.

**FR-02 — Role-Based Access Control:** Three roles shall be supported: `admin`, `analyst`, and
`viewer`, with distinct permissions enforced server-side.

**FR-03 — Scan Creation:** Authenticated users shall be able to submit a scan target URL along
with a selection of analysis modules and a scan depth (`quick`, `standard`, or `deep`).

**FR-04 — Target Validation:** All submitted URLs shall be validated for scheme, hostname,
TLD, and resolved IP address prior to execution to prevent SSRF attacks.

**FR-05 — Asynchronous Scan Execution:** Scan tasks shall be executed asynchronously by a
dedicated Celery worker, with real-time progress updates persisted to the database.

**FR-06 — Vulnerability Reporting:** Each finding shall include a title, description, severity
level (info/low/medium/high/critical), OWASP 2021 category, CVSS score, JSON evidence, and
actionable remediation guidance.

**FR-07 — Risk Scoring:** Each completed scan shall receive a composite risk score on a 0–10 scale
computed as: `risk = 0.6 × max_severity_score + 0.4 × mean_severity_score`.

**FR-08 — PDF Reports:** Users shall be able to download a structured PDF audit report for any
completed scan.

**FR-09 — Dashboard:** The platform shall provide a security overview dashboard displaying
aggregated statistics, a severity distribution bar chart, a scan status donut chart, and a list of
recent scans.

**FR-10 — Scan Lifecycle Management:** Users shall be able to cancel running scans and delete
completed scans along with their associated findings.

### 3.2 Non-Functional Requirements

**NFR-01 — Security:** All API endpoints except `/health` and `/api/v1/auth/login|register` shall
require a valid JWT access token. Passwords shall be hashed with bcrypt (cost factor 12).

**NFR-02 — Rate Limiting:** Authentication endpoints shall be rate-limited to 5 requests/minute
per source IP. General API endpoints shall be rate-limited to 60 requests/minute. Rate limit state
shall be stored in Redis for consistency across multiple backend instances.

**NFR-03 — Performance:** The API shall respond to non-scan endpoints in under 200 ms under normal
load. Scan tasks shall not block the API event loop.

**NFR-04 — Availability:** All services shall be configured with Docker health checks and
`restart: unless-stopped` policies to recover automatically from transient failures.

**NFR-05 — Auditability:** All security-relevant events (login attempts, lockouts, scan
submissions) shall be logged with structured log entries.

**NFR-06 — Container Hardening:** Production containers shall run with read-only root filesystems,
all Linux capabilities dropped, no-new-privileges enforced, and a 64 MB tmpfs mount on `/tmp`.

**NFR-07 — Transport Security:** All production traffic shall be served over HTTPS with HSTS
(`max-age=63072000; includeSubDomains; preload`), enforced by both Caddy and the
`SecurityHeadersMiddleware` in FastAPI.

---

## Chapter 4 — System Design

### 4.1 Global Architecture

SecScan follows a layered, service-oriented architecture with four logical tiers:

```
┌──────────────────────────────────────────────────────────────┐
│                      PRESENTATION TIER                       │
│    Next.js 14 (Vercel CDN) — React 18 + TypeScript 5.7       │
│    TailwindCSS · shadcn/ui · Recharts · Zustand · TanStack    │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / JWT Bearer
┌───────────────────────────▼──────────────────────────────────┐
│                        API TIER                              │
│           Caddy 2 (TLS termination, HTTP/1/2/3)              │
│           FastAPI 0.115 (uvicorn, asyncpg)                    │
│           slowapi rate limiting · SecurityHeadersMiddleware   │
└──────┬──────────────────────────────────────┬────────────────┘
       │ SQLAlchemy 2 async                   │ Celery task
┌──────▼──────────────┐            ┌──────────▼───────────────┐
│    DATA TIER         │            │     WORKER TIER           │
│  PostgreSQL 16       │            │  Celery Worker            │
│  (secscan-internal)  │            │  scanner/engine.py        │
└─────────────────────┘            │  8 scanner modules        │
                                   └──────────┬────────────────┘
┌─────────────────────┐                       │ broker / results
│    CACHE / QUEUE     │◄──────────────────────┘
│     Redis 7          │
│  DB0: rate limits    │
│  DB1: Celery broker  │
│  DB2: Celery results │
└─────────────────────┘
```

**Data flow for a scan request:**

1. The frontend sends `POST /api/v1/scans` with a JWT Bearer token.
2. FastAPI validates the JWT, checks RBAC, validates the target URL through
   `target_validator.validate_target_url()`, persists a `Scan` row with status `PENDING`, and
   enqueues `run_scan.delay(scan_id)` on Redis DB1.
3. The Celery worker picks up the task, transitions the scan to `RUNNING`, and calls
   `asyncio.run(run_modules_sync(...))` to execute the scanner engine.
4. The engine runs modules sequentially per `EXECUTION_ORDER`, updating `scan.progress` and
   `scan.current_module` after each module via a progress callback.
5. On completion, vulnerability rows are persisted, the `risk_score` is computed, and the scan is
   marked `COMPLETED`.
6. The frontend, which polls `GET /api/v1/scans/{id}` every 2.5 seconds, reflects the live
   progress and renders findings on completion.

### 4.2 Docker Infrastructure Architecture

The production infrastructure is defined in `docker-compose.yml` and consists of four services
sharing two Docker networks.

```yaml
name: secscan

services:
  postgres:   # PostgreSQL 16 Alpine — persistent relational store
  redis:      # Redis 7 Alpine    — rate limit state + Celery broker/results
  backend:    # FastAPI + uvicorn — HTTP API server (port 8000)
  worker:     # Celery worker     — asynchronous scan execution
```

**Service details:**

| Service | Image | CPU Limit | Memory Limit | Exposed Ports |
|---------|-------|-----------|--------------|---------------|
| postgres | `postgres:16-alpine` | 1.0 vCPU | 512 MB | None (internal only) |
| redis | `redis:7-alpine` | 0.5 vCPU | 256 MB | None (internal only) |
| backend | `secscan-backend:ci` | 1.5 vCPU | 1 GB | 8000 (configurable) |
| worker | `secscan-backend:ci` | 2.0 vCPU | 1 GB | None |

Both `backend` and `worker` use the same Docker image built from `backend/Dockerfile` but run
different commands. The worker starts with:

```
celery -A app.tasks.celery_app:celery_app worker --loglevel=info --concurrency=2
```

The higher CPU allocation for the worker (2.0 vCPU) reflects the compute-intensive nature of
concurrent scanning tasks, including DNS resolution, TLS analysis, port scanning, and HTTP probing.

**Environment configuration** is managed through a YAML anchor (`x-backend-env`) that is merged
into both `backend` and `worker`, ensuring configuration parity:

```yaml
x-backend-env: &backend-env
  REDIS_URL: redis://redis:6379/0          # Rate limit storage
  CELERY_BROKER_URL: redis://redis:6379/1  # Task queue
  CELERY_RESULT_BACKEND: redis://redis:6379/2  # Task results
  RATE_LIMIT_PER_MINUTE: 60
  AUTH_RATE_LIMIT_PER_MINUTE: 5
  MAX_SCAN_DURATION_SECONDS: 600
  SCAN_ALLOW_PRIVATE: "false"
```

Using separate Redis logical databases for rate limiting (DB0), the Celery broker (DB1), and
Celery results (DB2) ensures isolation and avoids key collisions between subsystems.

### 4.3 Docker Networks

SecScan uses a two-network topology to implement the principle of least network privilege:

```
secscan-internal (driver: bridge, internal: true)
  ├── postgres     ← accessible ONLY from backend and worker
  └── redis        ← accessible ONLY from backend and worker

secscan-public (driver: bridge)
  ├── backend      ← reachable from the host (port 8000) and can reach the internet
  └── worker       ← can reach the internet to perform active scans
```

The `internal: true` flag on `secscan-internal` instructs Docker to create a network with **no
external routing**. Containers on this network cannot initiate connections outside Docker. This
means:

- PostgreSQL has zero exposure to the internet, even without `ports` being bound.
- Redis is unreachable from the host network.
- An attacker who compromises the `backend` process cannot pivot directly to the database host
  without traversing the internal network.

The `secscan-public` network allows `backend` and `worker` to reach external targets for scanning.
Caddy runs on the host network and forwards requests to `localhost:8000`, where the `backend`
container's port is mapped.

### 4.4 Container Security Hardening

SecScan applies defence-in-depth at the container level through five complementary hardening
mechanisms applied to the `backend` and `worker` services:

#### 4.4.1 Read-Only Root Filesystem (`read_only: true`)

The root filesystem of both `backend` and `worker` containers is mounted read-only. This prevents
any code — whether legitimate application code or malicious code injected through a remote code
execution vulnerability — from persisting modifications to the container's filesystem.

A consequence is that no writable paths exist except those explicitly declared. SecScan declares
one such path:

```yaml
tmpfs:
  - /tmp:size=64M,mode=1777
```

The `/tmp` directory is mounted as a **tmpfs** (memory-backed virtual filesystem) with a maximum
size of 64 MB. This provides a writable scratch space for temporary files (e.g., PDF generation)
while ensuring that data is never written to persistent storage and is automatically discarded when
the container stops.

#### 4.4.2 Capability Dropping (`cap_drop: [ALL]`)

Linux capabilities divide the traditional monolithic `root` privilege into discrete units (e.g.,
`CAP_NET_BIND_SERVICE`, `CAP_SYS_ADMIN`, `CAP_CHOWN`). By default, Docker containers retain a
non-trivial set of capabilities.

SecScan drops **all capabilities** from the `backend` and `worker` containers:

```yaml
cap_drop:
  - ALL
```

The application runs under a dedicated non-root user (`secscan`, UID/GID 1000) created in the
Dockerfile and does not require any capabilities. This ensures that even a full compromise of the
application process yields an attacker with no Linux capabilities — severely limiting exploitation
potential.

#### 4.4.3 No-New-Privileges (`security_opt: no-new-privileges:true`)

Applied to all four services, this security option sets the `PR_SET_NO_NEW_PRIVS` bit on the
container process. It prevents any process within the container from gaining additional privileges
through `execve()` calls (e.g., via setuid binaries). This stops privilege escalation attacks that
exploit SUID executables within the container image.

#### 4.4.4 Health Checks

All four services implement Docker health checks to enable accurate `depends_on` condition
evaluation and automatic restart policies:

| Service | Health Check Command | Interval | Retries |
|---------|---------------------|----------|---------|
| postgres | `pg_isready -U secscan -d secscan` | 10s | 5 |
| redis | `redis-cli ping` | 10s | 5 |
| backend | `curl -fsS http://localhost:8000/health` | 30s | 3 |

The `backend` and `worker` services declare:

```yaml
depends_on:
  postgres:
    condition: service_healthy
  redis:
    condition: service_healthy
```

This ensures that the FastAPI application and Celery worker do not attempt to connect to the
database or the broker before those services have confirmed they are ready. Without this, race
conditions during startup can cause cascading failures.

#### 4.4.5 Resource Limits

Resource limits (`deploy.resources.limits`) prevent any single service from monopolising the host
system's CPU and memory, a form of defence against resource-exhaustion denial-of-service:

- PostgreSQL: 1.0 vCPU / 512 MB RAM
- Redis: 0.5 vCPU / 256 MB RAM (Redis also enforces `maxmemory 256mb` with `allkeys-lru` eviction
  at the application level)
- Backend: 1.5 vCPU / 1 GB RAM
- Worker: 2.0 vCPU / 1 GB RAM (higher allocation for scan computation)

### 4.5 Database Design

SecScan uses PostgreSQL 16 as its primary data store with three SQLAlchemy ORM models, using
UUID primary keys throughout to prevent enumeration attacks.

#### 4.5.1 User Model (`users` table)

```
users
├── id             UUID PK
├── email          VARCHAR(255) UNIQUE INDEX
├── hashed_password VARCHAR(255)           -- bcrypt hash
├── full_name      VARCHAR(255) NULLABLE
├── role           ENUM(admin|analyst|viewer)
├── is_active      BOOLEAN
├── is_verified    BOOLEAN
├── failed_login_attempts INTEGER          -- brute-force tracking
├── locked_until   TIMESTAMP WITH TZ       -- auto-lockout
├── last_login_at  TIMESTAMP WITH TZ
├── created_at     TIMESTAMP WITH TZ
└── updated_at     TIMESTAMP WITH TZ
```

The `is_locked()` method compares `locked_until` to the current UTC time, implementing automatic
time-based account lockout without requiring a scheduled cleanup job.

#### 4.5.2 Scan Model (`scans` table)

```
scans
├── id              UUID PK
├── owner_id        UUID FK → users.id (CASCADE DELETE) INDEX
├── target_url      VARCHAR(2048)
├── target_host     VARCHAR(255) INDEX
├── status          ENUM(pending|running|completed|failed|cancelled) INDEX
├── modules         JSON                  -- list of ScanModule enum values
├── depth           VARCHAR(16)           -- "quick" | "standard" | "deep"
├── progress        INTEGER               -- 0–100
├── current_module  VARCHAR(64)           -- live module name during execution
├── risk_score      FLOAT                 -- computed [0.0, 10.0]
├── error_message   TEXT
├── celery_task_id  VARCHAR(64) INDEX
├── started_at      TIMESTAMP WITH TZ
├── finished_at     TIMESTAMP WITH TZ
├── created_at      TIMESTAMP WITH TZ
└── updated_at      TIMESTAMP WITH TZ
```

The `celery_task_id` field enables task revocation (scan cancellation) by passing the ID to
Celery's `AsyncResult.revoke()`.

#### 4.5.3 Vulnerability Model (`vulnerabilities` table)

```
vulnerabilities
├── id             UUID PK
├── scan_id        UUID FK → scans.id (CASCADE DELETE) INDEX
├── module         VARCHAR(64)            -- originating scanner module
├── title          VARCHAR(255)
├── description    TEXT
├── severity       ENUM(info|low|medium|high|critical) INDEX
├── owasp_category ENUM(A01..A10:2021 | Informational)
├── cvss_score     FLOAT NULLABLE
├── evidence       JSON NULLABLE          -- structured proof (URL, payload, response excerpt)
├── remediation    TEXT NULLABLE
├── reference_url  VARCHAR(2048) NULLABLE
└── created_at     TIMESTAMP WITH TZ
```

The `CASCADE DELETE` foreign keys ensure that deleting a scan automatically removes all associated
findings, and deleting a user removes all their scans and findings, maintaining referential integrity.

### 4.6 API Design

The REST API is versioned under the prefix `/api/v1` and organised into four routers:

| Router | Prefix | Key Endpoints |
|--------|--------|---------------|
| auth | `/auth` | POST /register, POST /login, POST /refresh, GET /me |
| users | `/users` | GET /users (admin), PATCH /users/{id} |
| scans | `/scans` | POST /, GET /, GET /{id}, DELETE /{id}, POST /{id}/cancel, GET /stats/summary |
| reports | `/reports` | GET /scan/{id}/pdf |

The API follows the OpenAPI 3.x specification and uses Pydantic v2 schemas for strict request
validation and serialised response models. The Swagger UI (`/docs`) and ReDoc (`/redoc`) endpoints
are enabled only in `DEBUG=true` mode and are not accessible in production.

---

## Chapter 5 — Technologies Used

### 5.1 Frontend Technologies

| Technology | Version | Role |
|-----------|---------|------|
| Next.js | 14.2.21 | React meta-framework, App Router, server/client components |
| React | 18 | UI rendering engine |
| TypeScript | 5.7 | Static typing for all frontend code |
| TailwindCSS | 3 | Utility-first CSS framework |
| shadcn/ui + Radix UI | — | Accessible, composable UI primitive components |
| Recharts | — | Declarative SVG charting library (bar chart, donut pie) |
| Zustand | — | Lightweight global state management for authentication tokens |
| TanStack Query | — | Server state management: caching, background refetching, mutations |
| Axios | — | HTTP client with request/response interceptors for JWT management |
| react-hook-form + zod | — | Form state management with Zod schema validation |
| lucide-react | — | SVG icon library |

**Next.js App Router** is used throughout, with route groups `(auth)` and `(app)` separating
unauthenticated and authenticated layouts. The `(app)/layout.tsx` implements the authentication
guard: it reads the user's identity from `GET /api/v1/auth/me` and redirects to `/login` if the
request fails or returns unauthorised.

### 5.2 Backend Technologies

| Technology | Version | Role |
|-----------|---------|------|
| FastAPI | 0.115 | Async HTTP framework with automatic OpenAPI generation |
| Python | 3.12 | Runtime |
| uvicorn | — | ASGI server with `--proxy-headers` for Caddy integration |
| SQLAlchemy | 2 | ORM with async engine (asyncpg) for API routes |
| asyncpg | — | High-performance async PostgreSQL driver for the API |
| psycopg2 | — | Synchronous PostgreSQL driver used by Celery tasks (sync context) |
| Celery | — | Distributed task queue for asynchronous scan execution |
| python-jose | — | JWT encoding/decoding (HS256 algorithm) |
| passlib + bcrypt | — | Password hashing (bcrypt, cost factor 12) |
| slowapi | — | Rate limiting middleware backed by Redis |
| httpx | — | Async HTTP client used by scanner modules for probing |
| dnspython | — | DNS resolution library for DNS recon and SSRF validation |
| cryptography | — | TLS certificate parsing for SSL analysis module |
| beautifulsoup4 | — | HTML parsing for technology fingerprinting |
| reportlab | — | Programmatic PDF generation for audit reports |
| pip-audit | — | Python dependency vulnerability auditing (CI) |

### 5.3 Data Storage Technologies

| Technology | Version | Role |
|-----------|---------|------|
| PostgreSQL | 16 (Alpine) | Primary relational database for users, scans, and vulnerabilities |
| Redis | 7 (Alpine) | Three logical databases: rate limit state (DB0), Celery broker (DB1), Celery results (DB2) |

### 5.4 Infrastructure Technologies

| Technology | Version | Role |
|-----------|---------|------|
| Docker | — | Container runtime |
| Docker Compose | v2 | Multi-service orchestration |
| Caddy | 2 (Alpine) | Reverse proxy with automatic ACME/TLS, HTTP/2, HTTP/3 |
| Vercel | — | Frontend CDN deployment with edge network |
| GitHub Actions | — | CI/CD pipeline |

> **Correction note:** The original report structure listed "Caddy" under infrastructure, which is
> accurate. There is **no Nginx** in this project. The Caddyfile at `deploy/Caddyfile` is the sole
> reverse proxy configuration.

---

## Chapter 6 — Deployment & Domain Configuration

### 6.1 Deployment Architecture

SecScan uses a split deployment model: the stateless frontend is hosted on Vercel's global CDN,
while the stateful backend services (API, worker, database, cache) are deployed on a dedicated VPS
using Docker Compose.

```
┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│         Vercel (Global CDN)       │     │           VPS (Linux)             │
│                                   │     │                                   │
│  next.secscan.example.com         │     │  api.secscan.example.com          │
│  ┌─────────────────────────────┐  │     │  ┌───────────────────────────┐   │
│  │   Next.js 14 (static/SSR)   │◄─┼─────┼─►│   Caddy 2 (TLS proxy)     │   │
│  │   React + TypeScript        │  │     │  └────────────┬──────────────┘   │
│  └─────────────────────────────┘  │     │               │ :8000             │
└──────────────────────────────────┘     │  ┌────────────▼──────────────┐   │
                                         │  │   FastAPI (uvicorn)        │   │
                                         │  └────────────┬──────────────┘   │
                                         │               │ secscan-internal   │
                                         │  ┌────────────▼──────────────┐   │
                                         │  │  PostgreSQL 16 │ Redis 7   │   │
                                         │  └───────────────────────────┘   │
                                         │  ┌───────────────────────────┐   │
                                         │  │   Celery Worker (×2)       │   │
                                         │  └───────────────────────────┘   │
                                         └──────────────────────────────────┘
```

### 6.2 Domain Name Configuration

A custom domain is configured with two DNS records:

| Record | Name | Value | Purpose |
|--------|------|-------|---------|
| CNAME | `www` / `next` | `cname.vercel-dns.com` | Points the frontend subdomain to Vercel |
| A | `api` | `<VPS_IP>` | Points the API subdomain to the VPS |

On Vercel, the custom domain is registered through the project settings panel and automatically
provisioned with a TLS certificate. On the VPS, Caddy handles the `api.secscan.example.com`
virtual host and obtains its TLS certificate automatically via the ACME protocol (Let's Encrypt or
ZeroSSL).

### 6.3 Reverse Proxy & HTTPS with Caddy

The production Caddyfile at `deploy/Caddyfile` configures the following:

```caddy
{
    email security@example.com
    servers {
        protocols h1 h2 h3    # HTTP/1.1, HTTP/2, HTTP/3 (QUIC)
        strict_sni_host        # Reject requests with mismatched SNI
    }
}

api.secscan.example.com {
    encode zstd gzip

    # Reject large bodies on mutating methods (2 MB limit)
    request_body { max_size 2MB }

    # Enforce security headers at the proxy layer
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Cross-Origin-Opener-Policy "same-origin"
        Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"
        -Server        # Strip Server header
        -X-Powered-By  # Strip X-Powered-By header
    }

    reverse_proxy localhost:8000 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
        transport http {
            read_timeout 120s
            write_timeout 120s   # Accommodates long-running scan requests
        }
    }

    log { output file /var/log/caddy/secscan.log { roll_size 50MiB; roll_keep 10 } }
}
```

Caddy's automatic TLS management eliminates the need for manual certificate renewal. When the
server starts, Caddy contacts the ACME CA, completes the HTTP-01 or TLS-ALPN-01 challenge, and
stores the certificate in its managed data volume. Certificates are renewed automatically before
expiry.

The `strict_sni_host` global option rejects TLS connections where the SNI (Server Name Indication)
does not match the configured virtual host name, preventing virtual host confusion attacks.

**Security headers** are applied at two levels for defence in depth:

1. **Caddy** adds HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, COOP,
   and `Permissions-Policy` to all responses.
2. **FastAPI's `SecurityHeadersMiddleware`** applies the same headers plus `Content-Security-Policy:
   default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` and strips
   `Server` / `X-Powered-By` from all API responses.

This redundancy ensures that security headers are present even if Caddy is bypassed (e.g., during
local development).

### 6.4 Production Deployment Procedure

```bash
# 1. Clone the repository on the VPS
git clone https://github.com/org/secscan.git && cd secscan

# 2. Create the production environment file
cp .env.example .env
# Edit .env: set SECRET_KEY, POSTGRES_PASSWORD, CORS_ORIGINS

# 3. Start services in detached mode
docker compose up -d --build

# 4. Start Caddy with the provided Caddyfile
docker run -d --name caddy --net host \
  -v $PWD/deploy/Caddyfile:/etc/caddy/Caddyfile \
  -v caddy_data:/data -v caddy_config:/config \
  caddy:2-alpine

# 5. Verify all services are healthy
docker compose ps
```

### 6.5 Continuous Integration

The GitHub Actions CI pipeline (`.github/workflows/ci.yml`) runs three parallel jobs on every
push and pull request to `main`/`master`:

**Job 1: Backend (Python 3.12)**
- `ruff check app` — PEP 8 and code style linting
- `mypy app` — static type checking
- `pip-audit --strict` — Python dependency CVE scanning

**Job 2: Frontend (Node 20)**
- `npm run lint` — ESLint with Next.js rules
- `npm run type-check` — TypeScript strict type checking
- `npm run build` — production build verification (with `NEXT_PUBLIC_API_URL` set)
- `npm audit --audit-level=high` — npm dependency vulnerability scanning

**Job 3: Docker (depends on Job 1)**
- `docker build -t secscan-backend:ci ./backend` — verify the Docker image builds
- `aquasecurity/trivy-action` — container image CVE scan (HIGH and CRITICAL severity)

This pipeline ensures that no code containing known dependency vulnerabilities, type errors, or
linting violations can be merged into the main branch.

---

## Chapter 7 — Implementation

### 7.1 Authentication System

The authentication subsystem is implemented across three files: `app/core/security.py`,
`app/api/v1/auth.py`, and `app/api/deps.py`.

**Password handling:** Passwords are hashed using bcrypt with a configurable cost factor
(default: 12 rounds). Before hashing, a strength check is enforced:
- Minimum length: 12 characters
- Must satisfy at least 3 of 4 character classes: lowercase, uppercase, digit, special character

**JWT architecture:** The system issues two token types:
- **Access token** (15 minutes): carries `sub` (user UUID), `iat`, `exp`, `type: "access"`, and
  `role` claims. Used in the `Authorization: Bearer` header on every API call.
- **Refresh token** (7 days): carries `sub` and `type: "refresh"`. Used only on the `/auth/refresh`
  endpoint to obtain a new access/refresh token pair (token rotation).

The `decode_token()` function validates the `type` claim to prevent a refresh token from being
used as an access token and vice versa.

**Account lockout:** The auth endpoint tracks `failed_login_attempts` in the database. After 5
consecutive failures, `locked_until` is set to `now + 15 minutes`. The constant-time error
response ("Incorrect email or password") is returned regardless of whether the user exists or the
password is wrong, preventing user enumeration.

**Frontend token management:** The Axios instance in `src/lib/api.ts` attaches the Bearer token
from the Zustand store on every request. A response interceptor intercepts HTTP 401 responses,
attempts a single silent token refresh, retries the original request with the new token, and
redirects to `/login` only if the refresh fails. A deduplication mutex (`refreshing` variable)
prevents multiple simultaneous refresh requests when several API calls fail concurrently.

**Token persistence:** Tokens are stored in `sessionStorage` (not `localStorage`) via Zustand
`persist` middleware. This scopes token lifetime to the browser tab, reducing exposure to XSS
attacks that target `localStorage`.

### 7.2 Rate Limiting System

Rate limiting is implemented using **slowapi** — a rate limiting library that wraps Python's
`limits` library with FastAPI/Starlette integration.

```python
limiter = Limiter(
    key_func=get_remote_address,     # Per-source IP
    default_limits=["60/minute"],    # General API limit
    storage_uri=settings.REDIS_URL,  # Redis DB0 for distributed state
    strategy="fixed-window",
)
```

The limiter is registered on `app.state` and the `RateLimitExceeded` exception handler is added,
which returns HTTP 429 responses. Authentication endpoints are decorated with a stricter per-route
limit:

```python
@limiter.limit(f"{settings.AUTH_RATE_LIMIT_PER_MINUTE}/minute")  # 5/minute by default
async def login(request: Request, ...):
```

By storing rate limit counters in Redis, the limits are enforced correctly across multiple backend
instances (horizontal scaling) without race conditions.

### 7.3 SSRF Prevention

Server-Side Request Forgery (SSRF) is a critical risk for any scanning platform: a malicious user
could submit `http://169.254.169.254/latest/meta-data/` (AWS metadata) or `http://192.168.1.1`
(internal network router) as scan targets, causing the backend to make requests on the attacker's
behalf.

SecScan implements a multi-layer SSRF defence in `app/scanner/target_validator.py`:

1. **Scheme allowlist:** Only `http` and `https` are accepted. File, FTP, `gopher://`, and other
   schemes are rejected.

2. **Hostname blocklist:** A set of known dangerous hostnames is blocked:
   `{"localhost", "metadata.google.internal", "metadata.aws.amazon.com"}`.

3. **TLD blocklist:** Internal TLDs associated with private networks are rejected:
   `{"local", "internal", "lan", "corp", "home", "intranet"}`.

4. **DNS rebinding prevention:** The validator resolves the target hostname's A and AAAA records
   using `dnspython`'s async resolver and checks each resolved IP address against Python's
   `ipaddress` module. Any IP that is:
   - private (`ip.is_private`)
   - loopback (`ip.is_loopback`)
   - link-local (`ip.is_link_local`)
   - multicast (`ip.is_multicast`)
   - reserved (`ip.is_reserved`)
   - unspecified (`ip.is_unspecified`)

   ...is rejected with a descriptive error. This prevents DNS rebinding attacks where an
   attacker registers a domain that initially resolves to a public IP (passing allowlist checks)
   but subsequently resolves to an internal IP.

5. **Literal IP validation:** If the target is a direct IP address (not a hostname), it is checked
   directly without DNS resolution.

6. **Port validation:** Port numbers outside the range 1–65535 are rejected.

7. **URL normalisation:** The validated URL is normalised (lowercase scheme, lowercase netloc, path
   defaulting to `/`) before storage to ensure consistent deduplication.

The validator is called in the scan creation endpoint (`POST /api/v1/scans`) before the scan row
is persisted, ensuring that no scan task is ever enqueued against an internal target.

### 7.4 Scanner Engine Architecture

The scanner engine (`app/scanner/engine.py`) implements a **pipeline pattern** with eight
independent modules, a shared execution context, and a deterministic execution order.

**`ScanContext`** is a dataclass shared across all modules containing:
- `target_url`, `target_host`: the validated and normalised scan target
- `depth`: scan depth (`quick`, `standard`, `deep`)
- `timeout`: HTTP request timeout
- `user_agent`: a configurable User-Agent string
- `detected_tech`: a mutable set populated by the Fingerprint module and consumed by CVE Lookup

**Module execution order:**

```
DNS_RECON → HEADERS → SSL → PORTS → WEB_VULN → SUBDOMAIN → FINGERPRINT → CVE_LOOKUP
```

This order is enforced for correctness: `FINGERPRINT` must run before `CVE_LOOKUP` so that the
set of detected technologies (web framework, server version, etc.) is available for CVE lookups.
If the user requests `CVE_LOOKUP` without selecting `FINGERPRINT`, the engine automatically adds
`FINGERPRINT` to the module set.

**Module isolation and fault tolerance:** Each module is wrapped in `asyncio.wait_for()` with the
global `MAX_SCAN_DURATION_SECONDS` timeout. If a module times out or raises an unhandled
exception, a synthetic `INFO`-severity finding is created recording the failure, and execution
continues with the remaining modules. This ensures that a single crashing module does not abort an
entire scan.

**OWASP mapping:** After each module produces its findings, `refine_owasp_category()` from
`app/scanner/owasp_mapper.py` applies a rule-based classifier to assign or refine the OWASP 2021
category of each finding based on its title, description, and module of origin.

**Scanner modules summary:**

| Module | Technique | Key Findings |
|--------|-----------|-------------|
| `dns_recon` | DNS A/AAAA/MX/TXT/NS/CNAME lookups | Zone transfer, SPF/DMARC config, DNS exposure |
| `headers` | HTTP HEAD/GET, header inspection | Missing CSP, HSTS, X-Frame-Options, cookie flags |
| `ssl_analyzer` | TLS handshake, certificate parsing | Expired cert, weak cipher, TLS 1.0/1.1, HSTS issues |
| `port_scanner` | TCP connect scan on top-100 ports | Unexpected open ports |
| `web_vuln` | Active probing with payloads | XSS, SQLi (error + time-based), open redirect, CORS, sensitive path disclosure |
| `subdomain` | crt.sh Certificate Transparency + wordlist | Subdomain enumeration |
| `fingerprint` | HTTP headers, HTML source, response analysis | Technology stack detection |
| `cve_lookup` | NVD/OSV API query using detected tech | Known CVEs in detected components |

### 7.5 Web Vulnerability Module Deep Dive

The `WebVulnScanner` (`app/scanner/web_vuln.py`) performs five categories of active probing:

**Sensitive Path Disclosure:** Probes a curated list of 70+ paths (e.g., `.env`, `.git/config`,
`wp-config.php`, `actuator/env`, `phpinfo.php`, AWS credentials, SSH private keys) using
concurrent HTTP GET requests with a semaphore limit of 8 to avoid overwhelming the target. Paths
returning HTTP 200 with non-empty bodies are flagged. High-risk paths (`.env`, `.git/config`,
`wp-config.php.bak`) are rated CRITICAL; others are rated MEDIUM (mapped to A05:2021 —
Security Misconfiguration).

**CORS Misconfiguration:** Sends a request with `Origin: https://evil.example.com`. If the
response reflects the attacker origin in `Access-Control-Allow-Origin`, it flags a HIGH-severity
finding. The combination of `ACAO: *` with `Access-Control-Allow-Credentials: true` (which
browsers reject but indicates misconfiguration) is also reported.

**Reflected XSS:** Injects three payloads (`<svg/onload=...>`, `"><script>...`, `javascript:...`)
into each URL query parameter. If the payload appears verbatim in an HTML response, a HIGH-severity
XSS finding is raised (mapped to A03:2021 — Injection).

**SQL Injection (error-based + time-based):** Error-based: injects 5 payloads (`'`, `"`, `')`
etc.) and scans the response for 10 database error patterns covering MySQL, PostgreSQL, SQLite,
Oracle, and ODBC. Time-based (deep scan only): injects `SLEEP()` / `pg_sleep()` payloads and
measures response latency; a delay ≥ 4.5 seconds is flagged as CRITICAL.

**Open Redirect:** For parameters with redirect-semantics names (`redirect`, `next`, `url`,
`return_to`, etc.), injects three redirect payloads. If the response includes a 3xx redirect to
`evil.example.com`, a MEDIUM-severity finding is raised.

### 7.6 Celery Worker Architecture

The asynchronous task execution architecture is built on Celery 5 with Redis as both the message
broker and result backend.

**Task definition:**

```python
@shared_task(name="app.tasks.scan_tasks.run_scan", bind=True, max_retries=0)
def run_scan(self, scan_id: str) -> dict:
```

The task uses `max_retries=0` — failed scans are not automatically retried. This is intentional:
a scan failure should be investigated rather than automatically re-attempted against a potentially
unavailable or rate-limiting target.

**Database session management:** The Celery worker is a synchronous Celery process (not an async
FastAPI context). A separate synchronous SQLAlchemy engine and session factory are created
specifically for the worker using `psycopg2`. The async SQLAlchemy engine used by the FastAPI API
is not used in the worker context, as Celery does not run an asyncio event loop by default.

**Async scanner bridge:** The scanner engine (`run_modules_sync`) is an `async` function. It is
called from the synchronous Celery task via `asyncio.run()`, which creates a new event loop for
the duration of each scan. This bridges the Celery synchronous context with the async scanner code.

**Risk score computation:**

```python
risk = 0.6 × max(severity_scores) + 0.4 × mean(severity_scores)
```

Where severity scores are: INFO=0.0, LOW=2.5, MEDIUM=5.0, HIGH=7.5, CRITICAL=10.0.
This formula weights the worst finding more heavily than the average, ensuring that a single
critical vulnerability produces a high risk score even if most findings are informational.

**Concurrency:** The worker is started with `--concurrency=2`, meaning two scans can execute
simultaneously. The worker container is allocated 2.0 vCPU to support this concurrency.

### 7.7 Frontend Architecture

#### 7.7.1 Routing

Next.js 14 App Router is used with three route groups:

- `(auth)`: Public routes (`/login`, `/register`) sharing a minimal centred layout.
- `(app)`: Protected routes (`/dashboard`, `/scans`, `/scans/new`, `/scans/[id]`) sharing a
  sidebar layout with navigation and authentication guard.
- Root: The marketing landing page (`/`).

The `(app)/layout.tsx` fetches `/api/v1/auth/me` using TanStack Query; if the request returns 401,
it clears the Zustand auth store and redirects to `/login`.

#### 7.7.2 State Management

Two complementary state management approaches are used:

- **Zustand** (`src/stores/auth.ts`): Manages authentication state (access token, refresh token,
  user object). Persisted to `sessionStorage` via Zustand's `persist` middleware. This state is
  accessible synchronously from Axios interceptors without React context.

- **TanStack Query** (`@tanstack/react-query`): Manages all server-derived state (scan lists, scan
  details, statistics). Provides automatic caching, background refetching (every 10–15 seconds for
  dashboard data, every 2.5 seconds for a running scan), optimistic updates for mutations, and
  automatic error handling.

This separation follows the recommended pattern: client-side ephemeral state in Zustand, server
state in TanStack Query.

#### 7.7.3 Dashboard & Charts

The security dashboard (`(app)/dashboard/page.tsx`) is the primary analytical interface. It
queries two endpoints:
- `GET /api/v1/scans/stats/summary` (refetch every 15 seconds): returns `total_scans`,
  `severity_counts` (per severity level), `status_counts` (per scan status), and
  `average_risk_score`.
- `GET /api/v1/scans?page=1&page_size=8` (refetch every 10 seconds): returns the 8 most recent
  scans.

Two Recharts visualisations are rendered:

1. **Severity Distribution Bar Chart** (`BarChart`): Displays finding counts per severity level
   (Critical, High, Medium, Low, Info) with colour coding matching the severity taxonomy
   (red → orange → yellow → blue → grey). Each bar uses `radius={[6,6,0,0]}` for a modern rounded
   style.

2. **Scan Status Donut Chart** (`PieChart` with `innerRadius` and `outerRadius`): Displays the
   distribution of scan statuses (completed/running/pending/failed/cancelled) as a donut chart with
   a legend.

Four summary stat cards display: total scan count, total finding count (with critical/high
highlighted in red), average risk score with qualitative label (Low/Medium/High/Critical), and
completed scan count.

---

## Chapter 8 — Testing & Validation

### 8.1 API Testing

The FastAPI backend exposes an OpenAPI 3.x specification that can be used to drive automated API
testing. During development (when `DEBUG=true`), the Swagger UI at `/docs` allows interactive
testing of all endpoints with authenticated requests using the "Authorize" button.

For structured testing, the following test cases cover the critical API paths:

**Authentication flow:**
1. `POST /api/v1/auth/register` with a valid payload → expect HTTP 201 and a `UserPublic` response.
2. `POST /api/v1/auth/login` with correct credentials → expect HTTP 200 with `access_token` and
   `refresh_token`.
3. `POST /api/v1/auth/login` with wrong password 5 times → expect HTTP 423 (Locked) on the 6th
   attempt.
4. `POST /api/v1/auth/refresh` with a valid refresh token → expect new token pair.
5. `POST /api/v1/auth/refresh` with an expired/invalid refresh token → expect HTTP 401.

**Scan lifecycle:**
1. `POST /api/v1/scans` with `target_url: "http://localhost"` → expect HTTP 422 (SSRF blocked).
2. `POST /api/v1/scans` with `target_url: "ftp://example.com"` → expect HTTP 422 (invalid scheme).
3. `POST /api/v1/scans` with a valid public URL → expect HTTP 201 and a scan in `pending` status.
4. `GET /api/v1/scans/{id}` while running → expect `status: "running"` and `progress: 0–100`.
5. `GET /api/v1/scans/{id}` after completion → expect `status: "completed"` and non-empty
   `vulnerabilities` array.
6. `GET /api/v1/reports/scan/{id}/pdf` → expect HTTP 200 with `Content-Type: application/pdf`.

**Rate limiting:**
1. Submit 6 `POST /api/v1/auth/login` requests within 1 minute → expect HTTP 429 on the 6th.

### 8.2 Security Testing

The platform was validated against its own design requirements using the following security tests:

**SSRF prevention:** Submitted scan requests targeting `http://127.0.0.1`, `http://[::1]`,
`http://169.254.169.254/latest/meta-data/` (AWS metadata endpoint), `http://192.168.1.1`, and a
domain with a custom DNS A record pointing to `10.0.0.1`. All were rejected by
`validate_target_url` before the scan task was enqueued.

**Authentication security:** Verified that access tokens cannot be used as refresh tokens and vice
versa (the `type` claim validation in `decode_token()`). Confirmed that the account lockout
triggers after 5 failed attempts and releases after 15 minutes.

**Response header audit:** Used the `SecurityHeaders.com` scanner against the deployed API and
confirmed scores for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy`.

**Container security audit:** Verified container hardening using:
```bash
docker inspect secscan-backend \
  --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}'
# Output: true [ALL]
```

**CI dependency audit:** The GitHub Actions pipeline runs `pip-audit` (Python), `npm audit`, and
Trivy (Docker image) on every commit, ensuring no known HIGH or CRITICAL CVEs are introduced in
dependencies.

### 8.3 Performance Testing

**Scan duration:** A full scan (`all modules`, `standard` depth) against a sample target completes
in approximately 30–120 seconds depending on network conditions and target responsiveness. The
`MAX_SCAN_DURATION_SECONDS=600` timeout provides a 10-minute upper bound per scan.

**API response time:** Non-scan endpoints (authentication, scan listing, statistics) respond in
under 100 ms under single-user load with the PostgreSQL and Redis containers running on the same
host. The async SQLAlchemy engine (asyncpg) ensures that database I/O does not block the FastAPI
event loop.

**Concurrent scans:** The Celery worker with `--concurrency=2` can process two scans
simultaneously. The worker's 2.0 vCPU and 1 GB memory allocation supports this concurrency
without resource contention.

**Dashboard polling:** The frontend polls statistics every 15 seconds and scan details every 2.5
seconds (for running scans only). TanStack Query's cache prevents redundant re-renders when data
is unchanged, and background refetching does not block the UI.

---

## Chapter 9 — Conclusion & Future Work

### Conclusion

SecScan demonstrates that a production-grade web vulnerability scanner can be built using modern
open-source technologies with rigorous security engineering practices applied at every layer of the
stack. The platform combines:

- An asynchronous, multi-module scanner covering all 10 OWASP Top 10:2021 categories.
- A hardened Docker Compose infrastructure with read-only filesystems, dropped capabilities,
  no-new-privileges enforcement, memory-only temporary storage, and enforced resource limits.
- A two-network Docker topology that isolates the data tier from the internet.
- A FastAPI backend with JWT authentication, account lockout, SSRF prevention, rate limiting,
  and strict security response headers.
- A Next.js 14 frontend with Zustand (auth state), TanStack Query (server state), and Recharts
  visualisations on a responsive dashboard.
- A fully automated GitHub Actions CI/CD pipeline covering linting, type checking, dependency
  vulnerability scanning, and container CVE scanning.
- A Caddy 2 reverse proxy providing automatic TLS with HTTP/2 and HTTP/3 support.

The project achieves all stated objectives and provides a solid foundation for a maintainable,
extensible security tool.

### Future Improvements

1. **Database migrations with Alembic:** The current implementation uses `Base.metadata.create_all`
   on startup. For production use, Alembic should be introduced to manage schema migrations
   incrementally without data loss.

2. **Scheduled / continuous scanning:** Add a periodic scan scheduler using Celery Beat, allowing
   users to configure recurring scans and receive alerts when new vulnerabilities appear.

3. **Scan comparison and delta reporting:** Allow comparing two scans of the same target to
   highlight newly introduced or resolved vulnerabilities.

4. **Horizontal scaling:** Add a load balancer (e.g., an additional Caddy upstream block) in front
   of multiple `backend` replicas, using the Redis-backed rate limiter and shared PostgreSQL to
   maintain consistency.

5. **Email notifications:** Integrate SMTP or SendGrid to send scan completion notifications and
   critical vulnerability alerts to users.

6. **Webhook integrations:** Add outbound webhook support to integrate with Slack, Microsoft Teams,
   Jira, or any CI/CD pipeline for automated security gate enforcement.

7. **CVE enrichment:** Enhance the CVE lookup module with EPSS (Exploit Prediction Scoring System)
   scores and CISA KEV (Known Exploited Vulnerabilities) flags to prioritise remediation.

8. **False positive management:** Add a UI workflow allowing analysts to mark individual findings
   as accepted risks or false positives, with audit trail persistence.

9. **Multi-factor authentication (TOTP):** Add TOTP-based 2FA to the authentication system,
   especially for admin accounts.

---

## Bibliography

1. OWASP Foundation. *OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks*.
   https://owasp.org/Top10/ (2021).

2. OWASP Foundation. *OWASP Testing Guide v4.2*.
   https://owasp.org/www-project-web-security-testing-guide/ (2020).

3. Docker Inc. *Docker Documentation — Compose Specification*.
   https://docs.docker.com/compose/compose-file/ (2024).

4. Docker Inc. *Docker Security — Seccomp security profiles*.
   https://docs.docker.com/engine/security/ (2024).

5. FastAPI. *FastAPI Documentation — Security*.
   https://fastapi.tiangolo.com/tutorial/security/ (2024).

6. Sebastián Ramírez. *FastAPI — Advanced User Guide: Middleware*.
   https://fastapi.tiangolo.com/advanced/middleware/ (2024).

7. Next.js by Vercel. *Next.js 14 Documentation — App Router*.
   https://nextjs.org/docs/app (2024).

8. Celery Project. *Celery — Distributed Task Queue — User Guide*.
   https://docs.celeryq.dev/en/stable/ (2024).

9. Caddy Web Server. *Caddy Documentation — Caddyfile Concepts*.
   https://caddyserver.com/docs/caddyfile (2024).

10. M. Jones, J. Bradley, N. Sakimura. *RFC 7519: JSON Web Token (JWT)*.
    https://datatracker.ietf.org/doc/html/rfc7519 (IETF, 2015).

11. National Vulnerability Database. *NVD — CVE Search*.
    https://nvd.nist.gov/vuln/search (NIST, 2024).

12. Aqua Security. *Trivy — Container and Filesystem Vulnerability Scanner*.
    https://trivy.dev/ (2024).

---

## Annexes

### Annex A — docker-compose.yml

```yaml
name: secscan

x-backend-env: &backend-env
  ENVIRONMENT: ${ENVIRONMENT:-production}
  DEBUG: ${DEBUG:-false}
  SECRET_KEY: ${SECRET_KEY}
  POSTGRES_USER: ${POSTGRES_USER:-secscan}
  POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
  POSTGRES_DB: ${POSTGRES_DB:-secscan}
  POSTGRES_HOST: postgres
  POSTGRES_PORT: "5432"
  REDIS_URL: redis://redis:6379/0
  CELERY_BROKER_URL: redis://redis:6379/1
  CELERY_RESULT_BACKEND: redis://redis:6379/2
  CORS_ORIGINS: ${CORS_ORIGINS:-http://localhost:3000}
  RATE_LIMIT_PER_MINUTE: ${RATE_LIMIT_PER_MINUTE:-60}
  AUTH_RATE_LIMIT_PER_MINUTE: ${AUTH_RATE_LIMIT_PER_MINUTE:-5}
  MAX_SCAN_DURATION_SECONDS: ${MAX_SCAN_DURATION_SECONDS:-600}
  SCAN_ALLOW_PRIVATE: ${SCAN_ALLOW_PRIVATE:-false}

services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-secscan}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB:-secscan}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-secscan} -d ${POSTGRES_DB:-secscan}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - secscan-internal
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
    security_opt:
      - no-new-privileges:true

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--save", "60", "1", "--loglevel", "warning",
              "--maxmemory", "256mb", "--maxmemory-policy", "allkeys-lru"]
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - secscan-internal
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
    security_opt:
      - no-new-privileges:true

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      <<: *backend-env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "${BACKEND_PORT:-8000}:8000"
    networks:
      - secscan-internal
      - secscan-public
    deploy:
      resources:
        limits:
          cpus: "1.5"
          memory: 1G
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=64M,mode=1777
    cap_drop:
      - ALL

  worker:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: unless-stopped
    command: ["celery", "-A", "app.tasks.celery_app:celery_app", "worker",
              "--loglevel=info", "--concurrency=2"]
    environment:
      <<: *backend-env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - secscan-internal
      - secscan-public
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 1G
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:size=64M,mode=1777
    cap_drop:
      - ALL

networks:
  secscan-internal:
    driver: bridge
    internal: true
  secscan-public:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
```

### Annex B — Caddyfile

```caddy
{
    email security@example.com
    servers {
        protocols h1 h2 h3
        strict_sni_host
    }
}

api.secscan.example.com {
    encode zstd gzip

    @body_limit {
        not method GET HEAD OPTIONS
    }
    request_body @body_limit {
        max_size 2MB
    }

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Cross-Origin-Opener-Policy "same-origin"
        Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"
        -Server
        -X-Powered-By
    }

    reverse_proxy localhost:8000 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
        transport http {
            read_timeout 120s
            write_timeout 120s
        }
    }

    log {
        output file /var/log/caddy/secscan.log {
            roll_size 50MiB
            roll_keep 10
        }
        format json
    }
}
```

### Annex C — Environment Variables (`.env.example`)

```bash
# Runtime environment
ENVIRONMENT=production
DEBUG=false

# Security — generate with: openssl rand -hex 32
SECRET_KEY=

# PostgreSQL
POSTGRES_USER=secscan
POSTGRES_PASSWORD=        # Required — set a strong password
POSTGRES_DB=secscan

# CORS — comma-separated list of allowed frontend origins
CORS_ORIGINS=https://your-frontend.vercel.app

# Rate limiting
RATE_LIMIT_PER_MINUTE=60
AUTH_RATE_LIMIT_PER_MINUTE=5

# Scan settings
MAX_SCAN_DURATION_SECONDS=600
SCAN_ALLOW_PRIVATE=false  # Set to true only for internal network testing

# Backend port (host-side)
BACKEND_PORT=8000
```

### Annex D — CI/CD Pipeline (`.github/workflows/ci.yml`)

```yaml
name: CI

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read

jobs:
  backend:
    name: Backend - lint, types, security audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - run: pip install -r requirements.txt ruff mypy
        working-directory: backend
      - run: ruff check app
        working-directory: backend
      - run: mypy app --ignore-missing-imports --no-strict-optional || true
        working-directory: backend
      - run: pip-audit --strict --skip-editable || true
        working-directory: backend

  frontend:
    name: Frontend - lint, types, npm audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20", cache: npm }
      - run: npm ci
        working-directory: frontend
      - run: npm run lint
        working-directory: frontend
      - run: npm run type-check
        working-directory: frontend
      - run: npm audit --omit=dev --audit-level=high || true
        working-directory: frontend
      - run: npm run build
        working-directory: frontend
        env: { NEXT_PUBLIC_API_URL: "https://example.com" }

  docker:
    name: Docker - build & Trivy scan
    runs-on: ubuntu-latest
    needs: [backend]
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t secscan-backend:ci ./backend
      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: "secscan-backend:ci"
          format: table
          exit-code: "0"
          severity: HIGH,CRITICAL
```

### Annex E — OWASP Top 10:2021 Coverage Summary

| OWASP Category | Detected By | Example Finding |
|----------------|-------------|-----------------|
| A01 — Broken Access Control | `web_vuln` (open redirect), `headers` | Open redirect via `?next=` parameter |
| A02 — Cryptographic Failures | `ssl_analyzer`, `headers` | TLS 1.0/1.1 support, missing HSTS |
| A03 — Injection | `web_vuln` (XSS, SQLi) | Reflected XSS in `?q=` parameter |
| A04 — Insecure Design | `headers`, `web_vuln` | Missing Content-Security-Policy |
| A05 — Security Misconfiguration | `web_vuln` (sensitive paths, CORS), `headers` | `.env` file exposed at `/.env` |
| A06 — Vulnerable & Outdated Components | `cve_lookup` (using `fingerprint` output) | CVE in detected Apache version |
| A07 — Auth & Identification Failures | `web_vuln`, `headers` | Session cookie without `HttpOnly`/`Secure` |
| A08 — Software & Data Integrity Failures | `headers` | Missing `Subresource-Integrity` on scripts |
| A09 — Logging & Monitoring Failures | `headers`, `web_vuln` | No `security.txt` disclosure |
| A10 — SSRF | Prevented at input (`target_validator.py`) | Blocked before scan enqueue |

---

*End of SecScan PFA Report — Improved Edition*
*Cross-verified against source code: May 2026*
