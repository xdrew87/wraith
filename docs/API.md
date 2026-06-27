# WRAITH — REST API Reference

Base URL: `http://localhost:5050` (configurable via `--host` and `--port`)

All endpoints return JSON. Authentication is not required for local deployments (dashboard binds to `127.0.0.1` by default). Rate limits apply to prevent abuse.

---

## Health

### `GET /api/v1/health`

Returns service health. Not rate-limited.

**Response 200:**
```json
{ "status": "ok", "db": "ok" }
```

**Response 503** (database unavailable):
```json
{ "status": "degraded", "db": "error", "detail": "..." }
```

---

## Stats

### `GET /api/v1/stats`

Aggregate counts for the dashboard overview.

**Response:**
```json
{
  "total_findings": 142,
  "critical": 8,
  "high": 34,
  "medium": 67,
  "low": 33,
  "active_targets": 5,
  "pending_alerts": 3
}
```

---

## Findings

### `GET /api/v1/findings`

Paginated findings with optional filtering.

**Query Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | int | Results per page (1–500, default: 100) |
| `offset` | int | Pagination offset (default: 0) |
| `search` | string | Full-text search across target, value, breach_name, description |
| `severity` | string | Filter: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `source` | string | Filter by feed name (e.g., `HIBP`, `DeHashed`) |

**Response:**
```json
{
  "total": 142,
  "offset": 0,
  "limit": 50,
  "results": [
    {
      "id": 1,
      "target": "example.com",
      "source_feed": "HIBP",
      "exposure_type": "domain_breach",
      "value": "admin@example.com",
      "severity": "HIGH",
      "breach_name": "ExampleBreach",
      "breach_date": "2023-01-15",
      "description": "admin@example.com exposed in ExampleBreach",
      "first_seen_at": "2024-06-01 12:00:00"
    }
  ]
}
```

### `GET /api/v1/findings/<id>`

Single finding detail including attached investigation notes.

**Response:**
```json
{
  "id": 1,
  "target": "example.com",
  "source_feed": "HIBP",
  "exposure_type": "domain_breach",
  "value": "admin@example.com",
  "severity": "HIGH",
  "breach_name": "ExampleBreach",
  "breach_date": "2023-01-15",
  "description": "...",
  "first_seen_at": "2024-06-01 12:00:00",
  "notes": [
    { "id": 1, "content": "Confirmed with asset owner", "created_at": "2024-06-02 09:00:00" }
  ]
}
```

---

## Alerts

### `GET /api/v1/alerts`

Recent alerts.

**Query Parameters:** `limit` (1–500), `offset`

**Response:**
```json
{
  "total": 10,
  "results": [
    {
      "id": 1,
      "target": "example.com",
      "source_feed": "HIBP",
      "severity": "HIGH",
      "message": "[HIGH] HIBP: domain_breach — admin@example.com",
      "sent": false,
      "created_at": "2024-06-01 12:00:00"
    }
  ]
}
```

---

## Watch Targets

### `GET /api/v1/targets`

List all watch targets.

### `POST /api/v1/targets`

Add a watch target. Rate limited: 10/minute.

**Body:**
```json
{ "target": "example.com" }
```

**Response 201:**
```json
{ "status": "created", "id": 3 }
```

**Response 200** (already exists):
```json
{ "status": "exists", "id": 3 }
```

### `DELETE /api/v1/targets/<id>`

Deactivate a watch target. Rate limited: 10/minute.

**Response:**
```json
{ "status": "deactivated" }
```

---

## Feed Sources

### `GET /api/v1/sources`

Feed run status and result counts.

**Response:**
```json
[
  {
    "feed_name": "HIBP",
    "last_run_at": "2024-06-01 12:00:00",
    "last_status": "ok",
    "last_error": null,
    "total_results": 45
  }
]
```

---

## Timeline

### `GET /api/v1/timeline`

Findings grouped by date and severity for chart rendering.

**Query Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `days` | 30 | Number of days to look back (1–365) |
| `target` | — | Filter by specific target |

**Response:**
```json
{
  "days": 30,
  "data": [
    { "date": "2024-06-01", "total": 5, "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1 },
    { "date": "2024-06-02", "total": 3, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0 }
  ]
}
```

---

## Risk Scores

### `GET /api/v1/risk`

Computed risk score per target. Score = sum of weighted finding counts, capped at 100. Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1.

**Response:**
```json
[
  { "target": "example.com", "score": 87, "total": 12, "CRITICAL": 3, "HIGH": 5, "MEDIUM": 4, "LOW": 0 }
]
```

---

## Investigation Notes

### `GET /api/v1/notes`

**Query Parameters:** `finding_id` or `target`

### `POST /api/v1/notes`

Rate limited: 30/minute.

**Body:**
```json
{
  "finding_id": 1,
  "target": "example.com",
  "content": "Confirmed with asset owner — password changed"
}
```

**Response 201:**
```json
{ "id": 1, "finding_id": 1, "target": "example.com", "content": "...", "created_at": "..." }
```

### `DELETE /api/v1/notes/<id>`

---

## Saved Searches

### `GET /api/v1/searches`

### `POST /api/v1/searches`

Rate limited: 20/minute.

**Body:**
```json
{ "name": "Critical HIBP Findings", "filters": { "severity": "CRITICAL", "source": "HIBP", "search": "" } }
```

### `DELETE /api/v1/searches/<id>`

---

## Scan Trigger

### `POST /api/v1/scan`

Trigger a background scan for a target. Rate limited: 5/minute.

**Body:**
```json
{ "target": "example.com" }
```

**Response:**
```json
{ "status": "queued", "target": "example.com" }
```

---

## Error Responses

All errors return JSON:

```json
{ "error": "Description of the error" }
```

| Status | Meaning |
|---|---|
| 400 | Bad request — invalid or missing parameters |
| 404 | Resource not found |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
| 503 | Service unavailable (database error) |
