# ARKA Web Console — Backend API Mapping Reference

## 1. REST Endpoints Overview

| Frontend Route | Backend Method & Path | Description | Security Boundary |
|---|---|---|---|
| `/` (Dashboard) | `GET /api/engagements` | Fetch active engagement context | Read-only |
| `/` (Dashboard) | `GET /api/approvals?status=PENDING` | Fetch pending operator approvals | Read-only |
| `/` (Dashboard) | `GET /api/engagements/{id}/policy-decisions` | Fetch candidate request policy history | Read-only |
| `/assessments` | `GET /api/engagements` | List all engagements | Read-only |
| `/assessments/create` | `POST /api/engagements/preview-scope` | Compile & preview effective scope | Read-only validation |
| `/assessments/create` | `POST /api/engagements` | Create new engagement & scope | Authoritative creation |
| `/approvals` | `GET /api/approvals` | List approvals by status filter | Read-only |
| `/approvals` | `GET /api/approvals/{id}` | Inspect exact arguments & SHA-256 hash | Read-only |
| `/approvals` | `POST /api/approvals/{id}/decide` | Grant exact approval or reject | Human operator gate |
| `/attack-surface` | `GET /api/engagements/{id}/assets` | List discovered & authorized assets | Scoped read |
| `/attack-surface` | `GET /api/engagements/{id}/endpoints` | List mapped endpoints | Scoped read |
| `/attack-surface` | `GET /api/engagements/{id}/services` | List discovered ports & protocols | Scoped read |
| `/findings` | `GET /api/engagements/{id}/findings` | List epistemic findings | Scoped read |
| `/findings` | `GET /api/findings/{id}` | Inspect finding details & verification | Scoped read |
| `/findings` | `POST /api/findings/{id}/confirm` | Authoritatively promote to HUMAN_CONFIRMED | Human operator gate |
| `/graph` | `GET /api/engagements/{id}/graph` | Export Graphify nodes & edges for React Flow | Scoped read |
| `/operations` | `GET /api/engagements/{id}/tool-requests` | Full tool proposal telemetry | Scoped read |
| `/configuration` | `GET /api/configuration` | Retrieve providers, agents, tools, policy matrix | Read-only |
| `/reports` | `POST /api/reports/generate` | Compile markdown technical/executive report | Authoritative compilation |
| Global TopNav | `POST /api/engagements/halt-all` | Emergency killswitch execution | Deterministic halt |
| Global TopNav | `GET /api/stream`, `GET /api/engagements/{id}/stream` | Server-Sent Events (SSE) telemetry bus | Real-time streaming |
