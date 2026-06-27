# WRAITH — Architecture

## Overview

WRAITH is structured as a layered Python application with a clear separation between the intelligence collection engine, the persistence layer, the notification subsystem, and the presentation layer.

```
┌─────────────────────────────────────────────────────────┐
│                        CLI / API                        │
│         click commands  ·  Flask REST API               │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                    Aggregation Engine                    │
│  core/aggregator.py — async orchestrator                 │
│  Runs feeds in parallel via asyncio.gather()            │
│  Deduplicates by SHA-256 fingerprint hash               │
└──────┬──────────┬────────────┬──────────┬───────────────┘
       │          │            │          │
   ┌───▼──┐  ┌───▼────┐  ┌────▼───┐  ┌──▼────┐  ┌───────┐
   │ HIBP │  │DeHashed│  │ IntelX │  │Pastebn│  │GitHub │
   └───────┘  └────────┘  └────────┘  └───────┘  └───────┘
       All extend BaseFeed — retry, rate-limit, session mgmt
                            │
┌───────────────────────────▼─────────────────────────────┐
│                    Persistence Layer                     │
│  core/database.py — SQLAlchemy ORM                      │
│  Models: WatchTarget, ExposedCredential, Alert,         │
│          FeedStatus, InvestigationNote, SavedSearch      │
│  SQLite (default) or PostgreSQL                         │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                    Alerting System                       │
│  alerting/notifier.py                                   │
│  Channels: SMTP email, Slack webhook, Discord webhook   │
│  Webhook URLs validated against allowlist (anti-SSRF)   │
└─────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### `src/core/aggregator.py`
Central orchestrator. Receives a target string, spawns one coroutine per enabled feed via `asyncio.gather()` with `return_exceptions=True` (so one feed failure doesn't abort others), batch-deduplicates results against the database using a single `IN` query, then persists new findings.

### `src/core/database.py`
SQLAlchemy 2.0 ORM definitions. All models use `_utcnow()` which returns `datetime.now(timezone.utc).replace(tzinfo=None)` — timezone-safe but SQLite-compatible. The `db_session()` context manager ensures sessions are always closed and transactions are rolled back on error. Includes performance indexes on all frequently-filtered columns.

### `src/feeds/base.py`
`BaseFeed` provides:
- Shared `aiohttp.ClientSession` with SSL enforcement
- Semaphore-based concurrency limiting
- Exponential back-off retry (3 attempts, 2× backoff)
- Automatic 429 handling with `Retry-After` header
- `make_result()` — constructs a normalized result dict with SHA-256 hash fingerprint

### `src/cli/commands.py`
Click command group providing `init`, `scan`, `watch`, `unwatch`, `report`, `alerts`, `monitor`, `dashboard`. All commands load config → init DB → execute logic.

### `dashboard/backend/app.py`
Flask REST API. Security features:
- Rate limiting via Flask-Limiter (300/min default, 5/min for scan trigger)
- CORS restricted to configured origins only
- Security headers on every response (X-Frame-Options, CSP, etc.)
- Integer parameter clamping to prevent abuse
- Input length validation on POST bodies

### `dashboard/frontend/index.html`
Single-file SPA. All user-supplied data is passed through `escHtml()` before `innerHTML` insertion to prevent XSS. Tab-based navigation (Overview, Findings, Alerts, Targets, Timeline). Paginated findings table (50 per page). Findings export (CSV/JSON). Investigation notes via modal. Saved search persistence.

## Data Flow

```
1. scan <target>
   └── aggregate(target, config)
       ├── run_feed("hibp", ...) ──── async ──┐
       ├── run_feed("dehashed", ...) ── async ─┤
       ├── run_feed("intelx", ...) ─── async ─┤  gather()
       ├── run_feed("pastebin", ...) ── async ─┤
       └── run_feed("github", ...) ─── async ─┘
           │
           └── results[] → save_results()
               ├── Batch hash lookup (single IN query)
               ├── Insert new records
               └── queue_alerts() → dispatch Slack/Discord/Email
```

## Database Schema

See [Database.md](Database.md) for full schema documentation.

## Security Design Decisions

- **No plaintext credentials in logs**: `_mask_url()` strips credentials from DB URLs before logging.
- **SSRF prevention**: Webhook URLs are validated against an allowlist of known provider hostnames before dispatch.
- **HTML injection prevention**: Email alerts use `html.escape()` on all user-controlled data. Dashboard JS uses `escHtml()` consistently.
- **Rate limiting**: API endpoints are rate-limited at the application layer.
- **CORS**: Restricted to explicitly configured origins, not wildcard.
- **Bind address**: Dashboard defaults to `127.0.0.1` (loopback only) rather than `0.0.0.0`.
