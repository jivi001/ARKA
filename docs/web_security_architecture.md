# ARKA Web & API Security Architecture (Phase 3)

## Architectural Purpose
The Web & API Security subsystem provides autonomous reconnaissance, structural crawling, OpenAPI schema analysis, and GraphQL introspection across target environments.

In adherence to ARKA's core security invariants:
1. **The LLM is an untrusted reasoning engine and has ZERO execution or authorization authority.**
2. **`DISCOVERED != AUTHORIZED` — Discovered web assets never expand authorization bounds.**
3. **Defense in Depth**: SSRF protection, hop-by-hop redirect inspection, schema-level recursion bounds, and hard execution limits are strictly enforced at runtime.

---

## 1. Domain Models (`arka.app.web.models`)

### HTTP Specifications
- `HTTPRequest`: Immutable (`frozen=True`) request representation featuring normalized URLs (scheme lowercase, default port stripping, path traversal collapsing, query sorting, fragment dropping) and safety bounds on headers and body sizes.
- `HTTPResponse`: Captures status codes, latency, headers, and bounded body content. Automatically redacts sensitive authentication headers (`Authorization`, `Cookie`, `X-API-Key`, etc.).
- `HTTPTransaction`: Pairs a request and response with an execution timestamp, error state, and SHA-256 evidence record link.

### Parameter & Authentication Contexts
- `Parameter`: Strongly typed metadata for query, path, header, body, and form parameters.
- `AuthenticationContext` & `SessionContext`: Encapsulates credentials, bearer tokens, or session state. Redacts sensitive credentials in logs and audit representations.

---

## 2. Sandboxed HTTP Boundary (`arka.app.web.client`)

### Comprehensive SSRF Defense (`WebSSRFValidator`)
Before any TCP connection or DNS resolution is performed:
1. Validates URL scheme (`http` / `https`).
2. Performs DNS resolution to obtain all IPv4 and IPv6 target addresses.
3. Checks resolved IPs against:
   - Loopback (`127.0.0.0/8`, `::1`)
   - RFC 1918 Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local ranges (`169.254.0.0/16`, `fe80::/10`)
   - Multicast / Reserved blocks
   - Cloud metadata IP (`169.254.169.254`) and domain names (`metadata.google.internal`)
4. Blocks any private IP unless explicitly scoped in `ScopeGuard`.

### Controlled HTTP Client (`ControlledHTTPClient`)
- Disables automatic redirect following in the underlying HTTP client.
- Intercepts redirects manually. For every redirect hop:
  - Re-checks the new destination against `WebSSRFValidator`.
  - Re-evaluates destination against authoritative `ScopeGuard`.
  - Terminates request immediately with `ScopeViolation` or `SSRFViolation` if the redirect escapes scope.
- Enforces body response caps (`MAX_CAPTURED_BODY_BYTES`) to prevent memory exhaustion from decompression bombs.
- Automatically hashes requests and responses, committing immutable artifacts into `EvidenceStore`.

---

## 3. Crawler Subsystem (`arka.app.web.crawler`)

- **Structural HTML Parser** (`SafeHTMLParser`): Built on Python's standard library `html.parser` without native C dependencies. Extracts `<a href>`, `<form action>`, `<script src>`, `<link rel="stylesheet">`, and `<meta http-equiv="refresh">`.
- **Sitemap & Robots Parsing**: Safely parses `robots.txt` and uses `defusedxml` to parse `sitemap.xml` without XML entity expansion vulnerability risk.
- **BFS Crawl Engine** (`WebCrawler`): Traverses links using breadth-first search. Enforces:
  - `max_pages` (default: 50)
  - `max_depth` (default: 3)
  - `max_requests` (default: 100)
  - `same_origin_only` or same-subdomain restriction.
  - Per-hop ScopeGuard validation before enqueueing candidates.

---

## 4. Discovery Integration (`arka.app.web.discovery`)

- **Bridge to Canonical Entities** (`WebDiscoveryIntegrator`): Maps web crawler links, forms, and API operations into canonical Phase 2 domain entities:
  - `Endpoint`: Deterministic identity `generate_endpoint_id(asset_id, method, path)`.
  - `Asset`: Web host asset with `generate_asset_id(engagement_id, host)`.
  - `Service`: Web service (HTTP/HTTPS) on target port.
- **`DISCOVERED != AUTHORIZED` Flagging**: Every discovered entity is tagged with `discovered_not_authorized=True` in its metadata.
- **Evidence Provenance**: Connects every discovered endpoint to the cryptographic hash of the HTTP transaction in `EvidenceStore`.

---

## 5. Schema & API Analysis (`arka.app.web.openapi` & `arka.app.web.graphql`)

### OpenAPI / Swagger Analysis
- **Parser Security**: Safe JSON and YAML (`yaml.safe_load`) parser. Hard size cap (5 MB) and reference recursion depth limit (20).
- **External `$ref` Prohibition**: Explicitly rejects any `$ref` pointing to external URLs (`http://`, `https://`) or file paths (`file://`), preventing remote file inclusion and SSRF.
- **Server Scope Verification**: Discovered `servers` in OpenAPI schemas are verified against `ScopeGuard` before any endpoints are registered.

### GraphQL Analysis
- **Safe Introspection**: Probes `/graphql` using bounded introspection queries.
- **Type Extraction**: Maps object types, fields, arguments, queries, mutations, and subscriptions.
- **Risk Classification**: Mutations matching destructive verb patterns (`delete*`, `remove*`, `drop*`, `truncate*`, `purge*`, `kill*`) are classified as `RiskLevel.HIGH` and require human approval if dispatched.

---

## 6. Authoritative Security Pipeline

```
CandidateToolRequest (LLM Proposal)
          │
          ▼
    ToolRegistry (Schema validation & parameter verification)
          │
          ▼
     ScopeGuard (Authoritative CIDR / domain / URL boundary)
          │
          ▼
    PolicyEngine (Risk classification: READ_ONLY / MEDIUM / HIGH)
          │
          ▼
   ApprovalManager (Cryptographic human approval token validation)
          │
          ▼
   ExecutionManager (Sandboxed execution, audit logging, evidence capture)
```

No tool execution can bypass this pipeline.
