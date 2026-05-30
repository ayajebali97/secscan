# SecScan - Web Vulnerability Scanner & Security Audit Platform
## How to Run This Project

A full-stack web vulnerability scanner built with Next.js frontend and FastAPI backend, containerized with Docker.

---

## 📋 Prerequisites

Before running the project, ensure you have installed:

- **Docker** & **Docker Compose** v2+
- **Node.js** 20+ (for local frontend development, optional if using Docker)
- **Git**

### Verify Installation
```bash
docker --version
docker compose version
node --version  # Optional, only if running frontend locally
```

---

## 🚀 Quick Start (Recommended - Docker)

### 1. Clone & Navigate
```bash
cd d:\pfa\Pentesting-tool-web-application-Next.js-Fastapi
```

### 2. Configure Environment
```bash
# Create .env file from example (if not already exists)
cp .env.example .env

# Generate SECRET_KEY (run once and paste into .env)
python -c "import secrets; print(secrets.token_hex(32))"
```

Edit `.env` with the generated SECRET_KEY and set:
```env
ENVIRONMENT=development
DEBUG=false
SECRET_KEY=<your-generated-key>
POSTGRES_USER=secscan
POSTGRES_PASSWORD=secscan_local_dev
POSTGRES_DB=secscan
CORS_ORIGINS=http://localhost:3001
BACKEND_PORT=8001
```

### 3. Start Backend Stack (Docker)
```bash
docker compose up -d --build
```

This starts:
- FastAPI backend (port 8001)
- PostgreSQL database
- Redis cache
- Celery workers for scanning

### 4. Verify Backend is Running
```bash
docker compose ps
# Should see all containers as "Up" and "healthy"

# Test health endpoint
curl http://localhost:8001/health
```

### 5. Setup & Start Frontend

#### Option A: Local Development (Fastest)
```bash
cd frontend

# Copy environment file
copy .env.example .env.local

# Update to point to backend on port 8001
# File: frontend/.env.local
NEXT_PUBLIC_API_URL=http://localhost:8001

# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend will be available at: **http://localhost:3000** or **http://localhost:3001** (if port 3000 is in use)

#### Option B: Docker (Production-like)
```bash
docker compose -f docker-compose.yml up -d frontend
```

### 6. Access the Application
- **Dashboard**: http://localhost:3000 (or 3001)
- **API Docs**: http://localhost:8001/docs (if DEBUG=true)
- **Flower (Celery Monitoring)**: http://localhost:5555 (if enabled)

---

## 🔑 Default Credentials

If no users exist, you'll need to create one. Check the database setup logs:

```bash
docker compose logs backend | grep -i user
```

Or access the admin interface if available.

---

## 📁 Project Structure

```
.
├── backend/                 # FastAPI application
│   ├── app/
│   │   ├── main.py         # Entry point
│   │   ├── api/            # API routes
│   │   ├── scanner/        # Scanning modules
│   │   ├── core/           # Config, database
│   │   └── models/         # Database models
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/               # Next.js application
│   ├── src/
│   │   ├── app/           # Routes & layouts
│   │   ├── components/    # React components
│   │   └── lib/           # Utils & API client
│   ├── package.json
│   └── .env.local         # API URL config
│
├── docker-compose.yml     # Service orchestration
├── .env                   # Environment variables
└── .env.example          # Template
```

---

## 🛠️ Common Tasks

### View Backend Logs
```bash
docker compose logs backend -f
```

### View Frontend (if using Docker)
```bash
docker compose logs frontend -f
```

### Stop All Services
```bash
docker compose down
```

### Stop & Clean Data
```bash
docker compose down -v  # -v removes volumes/data
```

### Restart Backend
```bash
docker compose restart backend
```

### Access Database Shell
```bash
docker compose exec postgres psql -U secscan -d secscan
```

### Check Redis
```bash
docker compose exec redis redis-cli ping
```

---

## 🐛 Troubleshooting

### Login Failed / Network Error

**Problem**: `Login failed: POST http://localhost:8000 net::ERR_FAILED`

**Solution**: 
- Verify `.env` has correct `CORS_ORIGINS`: `http://localhost:3001`
- Verify `frontend/.env.local` has `NEXT_PUBLIC_API_URL=http://localhost:8001`
- Restart backend: `docker compose restart backend`
- Clear browser cache and refresh

### Port Already in Use

**Problem**: `port 8000 is already allocated`

**Solution**:
- Change `BACKEND_PORT` in `.env` to `8001` (or another free port)
- Update `frontend/.env.local` to match new port
- Restart: `docker compose down && docker compose up -d`

### Backend Unhealthy

**Problem**: `docker compose ps` shows backend not healthy

**Solution**:
```bash
# Check logs
docker compose logs backend

# Verify database is ready
docker compose exec postgres pg_isready

# Rebuild
docker compose down && docker compose up -d --build
```

### Frontend Won't Connect

**Problem**: `CORS policy: Response to preflight request doesn't pass access control check`

**Solution**:
1. Check `.env` CORS_ORIGINS includes your frontend URL
2. Backend must be restarted after changing `.env`
3. Verify browser isn't using cached headers (hard refresh: Ctrl+Shift+R)

### Database Connection Failed

**Problem**: `psycopg2.OperationalError: could not connect to server`

**Solution**:
```bash
# Wait for postgres to be ready
docker compose up postgres -d
sleep 10

# Then start backend
docker compose up -d backend
```

---

## 🔧 Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| ENVIRONMENT | production | development \| staging \| production |
| DEBUG | false | Enable FastAPI docs at /docs |
| SECRET_KEY | - | 64+ char random string (REQUIRED) |
| POSTGRES_USER | secscan | Database user |
| POSTGRES_PASSWORD | - | Database password (REQUIRED) |
| POSTGRES_DB | secscan | Database name |
| CORS_ORIGINS | http://localhost:3000 | Frontend URL for CORS |
| BACKEND_PORT | 8000 | Port for FastAPI (mapped to 8001 in this setup) |
| RATE_LIMIT_PER_MINUTE | 60 | API rate limit |
| MAX_SCAN_DURATION_SECONDS | 600 | Max scan time (10 minutes) |

---

## 📊 Architecture

```
┌─────────────────────────────────────────┐
│  Browser                                │
│  http://localhost:3000 (Frontend)       │
└──────────────────┬──────────────────────┘
                   │ HTTP/REST
                   ▼
┌─────────────────────────────────────────┐
│  FastAPI Backend                        │
│  http://localhost:8001                  │
│  - Authentication                       │
│  - Scan Management                      │
│  - Report Generation                    │
└──────────────────┬──────────────────────┘
         ┌────────┼────────┐
         ▼        ▼        ▼
    ┌────────┐ ┌──────┐ ┌──────────┐
    │ Postgres│ │Redis │ │ Celery   │
    │Database │ │Cache │ │ Workers  │
    └─────────┘ └──────┘ └──────────┘
```

---

## 🔐 Security Notes

- Never commit `.env` file with real credentials
- Use strong `SECRET_KEY` (64+ random characters)
- Always use HTTPS in production
- Set `DEBUG=false` in production
- Regularly update dependencies: `npm audit`, `pip-audit`
- Run scans only on systems you own or have permission to test

---

## 📝 Development Workflow

### Local Frontend Development (Fastest)

```bash
# Terminal 1: Backend
cd d:\pfa\Pentesting-tool-web-application-Next.js-Fastapi
docker compose up -d

# Terminal 2: Frontend
cd d:\pfa\Pentesting-tool-web-application-Next.js-Fastapi\frontend
npm run dev

# Now edit frontend code with hot reload at http://localhost:3000
```

### Local Backend Development

```bash
# Terminal 1: Dependencies
cd d:\pfa\Pentesting-tool-web-application-Next.js-Fastapi\backend
pip install -r requirements.txt

# Terminal 2: Start services (Postgres, Redis)
docker compose up postgres redis -d

# Terminal 3: Run backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 🚢 Deployment

For production deployment:

1. **Environment Variables**: Set all `.env` values for production
2. **Database**: Use managed PostgreSQL (AWS RDS, Azure Database, etc.)
3. **Redis**: Use managed Redis (AWS ElastiCache, Azure Cache, etc.)
4. **Frontend**: Deploy to Vercel, Netlify, or static hosting
5. **Backend**: Deploy to Docker (ECS, Kubernetes, VPS with Docker)
6. **SSL/TLS**: Use Let's Encrypt or managed certificates
7. **Domain**: Configure custom domain and DNS

See `deploy/` folder for deployment examples.

---

## 📚 Additional Resources

- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **Next.js Docs**: https://nextjs.org/docs
- **Docker Docs**: https://docs.docker.com/
- **PostgreSQL Docs**: https://www.postgresql.org/docs/

---

## 🤝 Support

For issues or questions:

1. Check `Troubleshooting` section above
2. Review Docker logs: `docker compose logs`
3. Verify `.env` configuration
4. Ensure all services are healthy: `docker compose ps`

---

## 📄 License

This project is part of a cybersecurity education initiative. Refer to LICENSE file for details.

---

**Last Updated**: May 30, 2026  
**Project Version**: 0.1.0
