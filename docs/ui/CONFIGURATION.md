# ARKA Console — Configuration & Deployment Guide

## 1. Prerequisites

- **Node.js**: >= 20.x (v24.21.0 recommended)
- **pnpm**: >= 9.x (v12.4.2 bundled)
- **Python**: >= 3.12 (with `uv` virtual environment active)
- **FastAPI Backend**: Running on `http://127.0.0.1:8000`

---

## 2. Directory Structure

```
ARKA/
├── arka/                # Authoritative Python / FastAPI backend
├── frontend/            # Tactical Security Operations Console (Next.js 16)
│   ├── src/
│   │   ├── app/         # App Router pages (/assessments, /approvals, etc.)
│   │   ├── components/  # Tactical UI & layout components
│   │   └── lib/         # API client, types, Zustand store, providers
│   ├── package.json
│   ├── next.config.ts   # API proxy configuration
│   └── tailwind.config.ts
├── tests/               # Backend regression & security tests
└── docs/ui/             # UI documentation & conformance reports
```

---

## 3. Running Locally

### Step 1: Start Backend
In the repository root:
```bash
uv run uvicorn arka.app.api.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 2: Start Console Dev Server
In another terminal:
```bash
cd frontend
pnpm dev
```
The console will be accessible at `http://localhost:3000`.

### Step 3: Production Build
To create an optimized production build:
```bash
cd frontend
pnpm build
```
All routes are pre-rendered statically with full dynamic client-side hydration against the FastAPI backend.
