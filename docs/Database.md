# WRAITH — Database Reference

## Overview

WRAITH uses SQLAlchemy ORM and supports SQLite (default, zero-config) and PostgreSQL (recommended for production). The schema is created automatically on first `init` via `Base.metadata.create_all()`.

**SQLite optimizations enabled at connect time:**
- `PRAGMA journal_mode=WAL` — allows concurrent reads during writes
- `PRAGMA foreign_keys=ON` — enforces referential integrity
- `check_same_thread=False` — required for multi-threaded Flask

---

## Models

### `watch_targets`

Domains and email addresses under continuous monitoring.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, autoincrement | Primary key |
| `target` | VARCHAR(255) | UNIQUE, NOT NULL, indexed | Domain or email address |
| `target_type` | VARCHAR(50) | NOT NULL | `domain` or `email` |
| `active` | BOOLEAN | default True, indexed | Whether actively monitored |
| `created_at` | DATETIME | default utcnow | Creation timestamp |
| `last_scanned_at` | DATETIME | nullable | Last completed scan |

---

### `exposed_credentials`

Normalized findings from all intelligence feeds.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, autoincrement | Primary key |
| `target` | VARCHAR(255) | NOT NULL, indexed | Scanned target |
| `source_feed` | VARCHAR(100) | NOT NULL, indexed | Feed name (HIBP, DeHashed, etc.) |
| `exposure_type` | VARCHAR(100) | NOT NULL | email_breach, plaintext_password, paste_hit, etc. |
| `value` | TEXT | nullable | Exposed value (may be truncated for display) |
| `severity` | VARCHAR(20) | NOT NULL, indexed | CRITICAL, HIGH, MEDIUM, LOW |
| `breach_name` | VARCHAR(255) | nullable | Source breach or dataset name |
| `breach_date` | VARCHAR(50) | nullable | Date of the original breach |
| `description` | TEXT | nullable | Human-readable finding description |
| `raw` | TEXT | nullable | JSON-serialized raw API response |
| `first_seen_at` | DATETIME | default utcnow, indexed | When Wraith first recorded this finding |
| `hash` | VARCHAR(64) | UNIQUE, NOT NULL | SHA-256 deduplication fingerprint |

**Composite index:** `(target, severity)` for dashboard filtered queries.

**Hash fingerprint:** `SHA-256(f"{target}:{source_feed}:{exposure_type}:{value}")`

---

### `alerts`

Queued and dispatched notification records.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, autoincrement | Primary key |
| `target` | VARCHAR(255) | NOT NULL, indexed | Target that triggered the alert |
| `source_feed` | VARCHAR(100) | NOT NULL | Feed that produced the finding |
| `severity` | VARCHAR(20) | NOT NULL | Alert severity level |
| `message` | TEXT | NOT NULL | Alert message text |
| `sent` | BOOLEAN | default False, indexed | Whether notification was dispatched |
| `created_at` | DATETIME | default utcnow, indexed | Alert creation timestamp |

---

### `feed_status`

Runtime status of each intelligence feed.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, autoincrement | Primary key |
| `feed_name` | VARCHAR(100) | UNIQUE, NOT NULL | Feed identifier |
| `last_run_at` | DATETIME | nullable | Last execution timestamp |
| `last_status` | VARCHAR(50) | nullable | `ok` or `error` |
| `last_error` | TEXT | nullable | Error message if status is `error` |
| `total_results` | INTEGER | default 0 | Cumulative result count |

---

### `investigation_notes`

Analyst annotations attached to findings or targets.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, autoincrement | Primary key |
| `finding_id` | INTEGER | nullable, indexed | Foreign key to `exposed_credentials.id` (NULL = target-level note) |
| `target` | VARCHAR(255) | NOT NULL, indexed | Target this note relates to |
| `content` | TEXT | NOT NULL | Note body (max 10,000 chars enforced at API layer) |
| `created_at` | DATETIME | default utcnow | Creation timestamp |
| `updated_at` | DATETIME | default utcnow, onupdate | Last modification timestamp |

---

### `saved_searches`

Persisted filter states for quick dashboard access.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | INTEGER | PK, autoincrement | Primary key |
| `name` | VARCHAR(255) | NOT NULL | User-provided search name |
| `filters` | TEXT | NOT NULL | JSON-serialized filter dict (search, severity, source) |
| `created_at` | DATETIME | default utcnow | Creation timestamp |

---

## Indexes Summary

| Table | Index | Columns | Purpose |
|---|---|---|---|
| `watch_targets` | unique | `target` | Prevent duplicate targets |
| `watch_targets` | ix | `active` | Filter active targets for monitor loop |
| `exposed_credentials` | unique | `hash` | Deduplication constraint |
| `exposed_credentials` | ix_ec_target | `target` | Filter by target |
| `exposed_credentials` | ix_ec_severity | `severity` | Filter by severity |
| `exposed_credentials` | ix_ec_source_feed | `source_feed` | Filter by feed |
| `exposed_credentials` | ix_ec_first_seen_at | `first_seen_at` | Date range queries, ordering |
| `exposed_credentials` | ix_ec_target_severity | `target, severity` | Composite filter for risk queries |
| `alerts` | ix_alert_target | `target` | Filter alerts by target |
| `alerts` | ix_alert_created_at | `created_at` | Date ordering |
| `alerts` | ix_alert_sent | `sent` | Filter unsent alerts |
| `investigation_notes` | ix_note_finding_id | `finding_id` | Look up notes for a finding |
| `investigation_notes` | ix_note_target | `target` | Look up notes for a target |

---

## Migration Notes

WRAITH does not use Alembic — `Base.metadata.create_all()` is idempotent and safe to run on an existing database (it only creates missing tables/indexes). When adding new columns to existing tables in production, apply them manually or use a migration tool like Alembic.

## PostgreSQL Setup

```bash
createdb wraith
export DATABASE_URL="postgresql+psycopg2://user:password@localhost/wraith"
py src/main.py init
```

Install the driver: `pip install psycopg2-binary`
