# Phishing Analyzer — Backend

FastAPI-based phishing analysis engine. Accepts URLs, domains, IPs, and raw email headers and runs them through a multi-source threat intelligence pipeline to produce a structured risk verdict.

---

## Architecture

```
app/
├── core/
│   ├── config.py       # Pydantic settings — single source of truth for all env vars
│   └── logging.py      # Structured logging (JSON in prod, rich console in dev)
├── routers/
│   ├── health.py       # GET /api/v1/health — dependency status + uptime
│   └── scan.py         # POST /api/v1/scan — submit artifact for analysis
├── schemas/
│   ├── health.py       # HealthResponse Pydantic models
│   └── scan.py         # ScanRequest / ScanResponse Pydantic models
├── services/
│   └── scan_service.py # Business logic orchestrator (stubs for Phase 1)
└── main.py             # FastAPI app factory — CORS, routers, lifespan hooks
```

**Design principles:**
- Routers are thin HTTP adapters — no business logic
- Services own all analysis logic — independently testable
- Schemas define the API contract — validated at the boundary
- Config is validated at startup — misconfigured env fails fast

---

## Quick Start (Local Development)

### Prerequisites

- Python 3.12+
- pip

### 1. Clone and navigate

```bash
cd backend
```

### 2. Create a virtual environment

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 5. Run the development server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server starts at **http://localhost:8000**

### 6. Test the endpoints

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Submit a scan
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://suspicious-login.example.com", "scan_type": "url"}'
```

### 7. Interactive API docs

Open **http://localhost:8000/docs** in your browser (disabled in production).

---

## Docker

```bash
# Build
docker build -t phishing-analyzer-backend .

# Run
docker run -p 8000:8000 --env-file .env phishing-analyzer-backend
```

---

## Environment Variables

See `.env.example` for the full list with descriptions. Required variables for Phase 1:

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` \| `staging` \| `production` |
| `SECRET_KEY` | — | Random secret, required in production |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated frontend origins for CORS |
| `LOG_FORMAT` | `console` | `json` for production, `console` for development |

---

## Development Phases

| Phase | Status | Description |
|---|---|---|
| **1** | ✅ Complete | Backend foundation — FastAPI, config, logging, health, scan stub |
| **2** | ✅ Complete | Threat intel — VirusTotal, AbuseIPDB, WHOIS, SPF/DKIM/DMARC, risk engine |
| **3** | ✅ Complete | PostgreSQL + Redis — persistence, caching, deduplication, scan history |
| **4** | ✅ Complete | AI verdict — Gemini 2.0 Flash phishing analysis with structured JSON output |
| **5** | ✅ Complete | React frontend — SOC dashboard UI (Vite + React + Tailwind) |

## Running with Docker (Phase 3+)

```bash
# From the project root (phishing-analyzer/)
docker-compose up

# API is available at http://localhost:8000
# PostgreSQL at localhost:5432
# Redis at localhost:6379
```

## Running database migrations manually (Alembic)

```bash
cd backend

# Apply all pending migrations
alembic upgrade head

# Auto-generate a new migration after model changes
alembic revision --autogenerate -m "add column X"

# Roll back one migration
alembic downgrade -1
```
