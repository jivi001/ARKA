# REST API Reference

ARKA exposes an asynchronous REST API built with **FastAPI**.

Interactive Swagger documentation is available at `http://localhost:8000/docs` when the server is running.

---

## 1. System Endpoints

### `GET /health`
Returns system health, database status, and redis connectivity.

- **Response `200 OK`**:
  ```json
  {
    "status": "healthy",
    "version": "0.1.0",
    "database": "connected",
    "redis": "connected",
    "timestamp": "2026-08-19T12:00:00Z"
  }
  ```

---

## 2. Engagement Management Endpoints

### `POST /engagements`
Creates a new security assessment engagement.

- **Request Body**:
  ```json
  {
    "name": "Q3 Infrastructure Audit",
    "objective": "Identify exposed services and web vulnerabilities",
    "scope": {
      "includes": {
        "domains": ["target.example.com"],
        "subdomains_allowed": true,
        "cidrs": ["192.168.1.0/24"]
      },
      "excludes": {
        "ip_addresses": ["192.168.1.1"]
      }
    }
  }
  ```
- **Response `201 Created`**: Returns created `EngagementState` object with UUID.

### `GET /engagements/{id}`
Returns engagement metadata, status, and current task summary.

### `POST /engagements/{id}/start`
Transitions engagement status to `active` and launches the orchestrator graph.

### `POST /engagements/{id}/pause`
Pauses active execution loops.

### `POST /engagements/{id}/stop`
Terminates the engagement and generates final audit summaries.

---

## 3. Tasks & Approvals Endpoints

### `GET /engagements/{id}/tasks`
Lists all tasks scheduled or completed for an engagement.

### `GET /approvals`
Lists pending or decided human-in-the-loop approval requests.

### `POST /approvals/{id}/decide`
Submits an approval decision (`GRANTED` or `REJECTED`).

- **Request Body**:
  ```json
  {
    "status": "granted",
    "decided_by": "security-lead@company.com",
    "rejection_reason": null
  }
  ```

---

## 4. Audit Trail Endpoints

### `GET /engagements/{id}/audit`
Retrieves sanitized, immutable audit trail records for an engagement.
