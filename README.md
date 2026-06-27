# WRAITH

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/xdrew87/wraith/actions/workflows/ci.yml/badge.svg)](https://github.com/xdrew87/wraith/actions)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-red)]()

**WRAITH** is an enterprise-grade credential exposure and breach intelligence platform for Security Operations Centers, Threat Intelligence teams, Red Teams, Incident Responders, and OSINT investigators. It aggregates exposure data from multiple intelligence sources, persists findings to a database, triggers real-time alerts, and surfaces everything through a modern dark-mode web dashboard.

> ⚠️ **Authorized use only.** WRAITH is designed exclusively for monitoring domains and email addresses you own or have explicit permission to assess.

---

## Features

| Category | Capability |
|---|---|
| **Intelligence Feeds** | HIBP v3, DeHashed, Intelligence X, Pastebin scrape, GitHub code search |
| **Target Types** | Domain monitoring, email address monitoring |
| **Detection** | Plaintext passwords, hashed passwords, email exposures, paste hits, code secrets (GitHub tokens, AWS keys, private keys, API keys) |
| **Severity Engine** | Automatic CRITICAL / HIGH / MEDIUM / LOW classification per finding |
| **Deduplication** | SHA-256 fingerprint hashing prevents duplicate findings |
| **Storage** | SQLite (default) or PostgreSQL via SQLAlchemy — fully indexed |
| **Alerting** | Email (SMTP/TLS), Slack webhook, Discord webhook |
| **Dashboard** | Dark-mode SPA — Overview, Findings, Alerts, Targets, Timeline tabs |
| **Analytics** | Risk scoring per target, severity distribution, 30/90-day timeline |
| **Investigation** | Per-finding notes, saved searches, finding export (JSON/CSV) |
| **API** | RESTful JSON API with rate limiting and security headers |
| **CLI** | Rich terminal output, table/JSON/CSV export, continuous monitor daemon |
| **Deployment** | Docker + docker-compose ready |

---

## Architecture

```
wraith/
├── src/
│   ├── main.py                  # CLI entry point
│   ├── cli/commands.py          # Click command group
│   ├── core/
│   │   ├── aggregator.py        # Async multi-feed orchestration
│   │   ├── config.py            # YAML + env-var configuration loader
│   │   ├── database.py          # SQLAlchemy models + session management
│   │   ├── monitor.py           # Continuous monitoring daemon
│   │   └── reporter.py          # Rich table / JSON / CSV output
│   ├── feeds/
│   │   ├── base.py              # BaseFeed with retry, rate-limit handling
│   │   ├── hibp.py              # HaveIBeenPwned v3
│   │   ├── dehashed.py          # DeHashed API
│   │   ├── intelx.py            # Intelligence X
│   │   ├── pastebin.py          # Pastebin scrape API
│   │   └── github.py            # GitHub code search + secret detection
│   └── alerting/notifier.py     # Slack / Discord / SMTP alerting
├── dashboard/
│   ├── backend/app.py           # Flask REST API
│   └── frontend/index.html      # Single-file SPA dashboard
├── tests/                       # pytest test suite
├── docs/                        # Architecture, API, deployment docs
├── config.yaml                  # Default configuration
└── .env.example                 # Environment variable template
```

Feed results flow: `CLI scan` → `aggregator.aggregate()` → `run_feed()` per source → `save_results()` (dedup by hash) → `queue_alerts()` → dispatch (Slack/Discord/Email).

---

## Screenshots

> Dashboard screenshots — run `py src/main.py dashboard` and navigate to `http://localhost:5050`

---

## Quick Start

### Prerequisites
- Python 3.10 or later
- API keys for the intelligence feeds you want to use (see [Configuration](#configuration))

### Installation

```bash
git clone https://github.com/xdrew87/wraith.git
cd wraith
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
py src/main.py init
```

### First Scan

```bash
# Scan a domain once
py src/main.py scan example.com

# Scan a specific email
py src/main.py scan user@example.com

# Scan with specific feeds only
py src/main.py scan example.com --feeds hibp,dehashed

# Output as JSON
py src/main.py scan example.com --format json --output results.json
```

### Continuous Monitoring

```bash
# Add targets to the watch list
py src/main.py watch example.com
py src/main.py watch admin@example.com

# Start the monitor daemon (scans all watch targets on configured interval)
py src/main.py monitor

# Remove a target
py src/main.py unwatch example.com
```

### Web Dashboard

```bash
py src/main.py dashboard --port 5050
# Open http://localhost:5050
```

---

## Configuration

Edit `config.yaml` for persistent defaults. Set environment variables to override — useful for secrets and CI/CD.

### Environment Variables

| Variable | Config Path | Description |
|---|---|---|
| `HIBP_API_KEY` | `feeds.hibp.api_key` | HaveIBeenPwned v3 API key |
| `DEHASHED_EMAIL` | `feeds.dehashed.email` | DeHashed account email |
| `DEHASHED_API_KEY` | `feeds.dehashed.api_key` | DeHashed API key |
| `INTELX_API_KEY` | `feeds.intelx.api_key` | Intelligence X API key |
| `GITHUB_TOKEN` | `feeds.github.token` | GitHub personal access token (read:repo) |
| `DATABASE_URL` | `database.url` | SQLAlchemy URL (leave blank for SQLite) |
| `SMTP_HOST` | `alerting.smtp.host` | SMTP server host |
| `SMTP_PORT` | `alerting.smtp.port` | SMTP server port (default: 587) |
| `SMTP_USER` | `alerting.smtp.user` | SMTP username |
| `SMTP_PASSWORD` | `alerting.smtp.password` | SMTP password |
| `ALERT_FROM_EMAIL` | `alerting.smtp.from_email` | Alert sender address |
| `ALERT_TO_EMAIL` | `alerting.smtp.to_email` | Alert recipient address |
| `SLACK_WEBHOOK_URL` | `alerting.slack.webhook_url` | Slack incoming webhook URL |
| `DISCORD_WEBHOOK_URL` | `alerting.discord.webhook_url` | Discord webhook URL |
| `DASHBOARD_ALLOWED_ORIGINS` | — | Comma-separated CORS origins (default: `http://localhost:5050`) |

### config.yaml Reference

```yaml
database:
  sqlite_path: "wraith.db"   # SQLite file path (ignored if DATABASE_URL is set)

feeds:
  hibp:
    enabled: true
    rate_limit: 1            # Requests per second (free tier limit)

monitor:
  interval_seconds: 3600    # How often to re-scan watch targets

alerting:
  enabled: true
  min_severity: "MEDIUM"    # Only alert on findings at or above this severity

logging:
  level: "INFO"
  file: "logs/wraith.log"
  max_bytes: 10485760       # 10 MB per file
  backup_count: 5
```

---

## Docker

```bash
# Build and run
docker compose up -d

# View logs
docker compose logs -f

# Run a scan inside the container
docker compose exec wraith py src/main.py scan example.com
```

---

## CLI Reference

```
Commands:
  init        Initialize the WRAITH database
  scan        Scan a domain or email for credential exposures
  watch       Add a target to the continuous watch list
  unwatch     Remove a target from the watch list
  report      Display credential exposure findings from the database
  alerts      Display recent alerts
  monitor     Run the continuous monitoring daemon
  dashboard   Launch the web dashboard

Options (all commands):
  --config PATH    Path to config.yaml (default: auto-detected)

scan options:
  --feeds TEXT     Comma-separated list of feeds (hibp,dehashed,intelx,pastebin,github)
  --format TEXT    Output format: table | json | csv (default: table)
  --output PATH    Write output to file

report options:
  --target TEXT    Filter by target
  --severity TEXT  Filter by severity: LOW | MEDIUM | HIGH | CRITICAL
  --format TEXT    Output format: table | json | csv
  --limit INT      Maximum results (default: 100)

dashboard options:
  --port INT       Port to listen on (default: 5050)
  --host TEXT      Bind address (default: 127.0.0.1)
```

---

## Dashboard API

Base URL: `http://localhost:5050`

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/health` | Service health check |
| GET | `/api/v1/stats` | Aggregate counts by severity |
| GET | `/api/v1/findings` | Paginated findings with search/filter |
| GET | `/api/v1/findings/<id>` | Single finding detail with notes |
| GET | `/api/v1/alerts` | Recent alerts |
| GET | `/api/v1/targets` | Watch targets |
| POST | `/api/v1/targets` | Add a watch target |
| DELETE | `/api/v1/targets/<id>` | Deactivate a watch target |
| GET | `/api/v1/sources` | Feed status |
| GET | `/api/v1/timeline` | Findings over time (by day, by severity) |
| GET | `/api/v1/risk` | Risk scores per target |
| GET | `/api/v1/notes` | Investigation notes |
| POST | `/api/v1/notes` | Create a note |
| DELETE | `/api/v1/notes/<id>` | Delete a note |
| GET | `/api/v1/searches` | Saved searches |
| POST | `/api/v1/searches` | Save a search |
| DELETE | `/api/v1/searches/<id>` | Delete a saved search |
| POST | `/api/v1/scan` | Trigger a background scan |

See [docs/API.md](docs/API.md) for full request/response documentation.

---

## Output Example

```
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
 ...

Scanning: example.com (type: domain)
╭─────────────────────────────────────────────────────────────────────╮
│                  WRAITH — 5 Finding(s)                              │
├───────────────┬──────────┬───────────────────┬────────────┬─────────┤
│ Target        │ Source   │ Type              │ Severity   │ Breach  │
├───────────────┼──────────┼───────────────────┼────────────┼─────────┤
│ example.com   │ HIBP     │ domain_breach     │ HIGH       │ Test    │
│ example.com   │ DeHashed │ plaintext_password│ CRITICAL   │ TestDB  │
│ example.com   │ IntelX   │ paste_hit         │ HIGH       │ pastes  │
│ example.com   │ GitHub   │ aws_access_key    │ CRITICAL   │ user/r  │
│ example.com   │ Pastebin │ paste_email       │ HIGH       │ pb:xyz  │
╰───────────────┴──────────┴───────────────────┴────────────┴─────────╯

Summary: 5 findings — 2 CRITICAL | 3 HIGH
```

---

## Roadmap

- [ ] IOC correlation engine (link findings to threat actor TTPs)
- [ ] Webhook receiver (accept external breach notifications)
- [ ] MISP integration
- [ ] TheHive integration
- [ ] OpenCTI integration
- [ ] User authentication for multi-user dashboard deployments
- [ ] Additional feeds: LeakIX, Breachsense, Spycloud

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests welcome. Please open an issue first for major changes.

---

## ⚠️ Authorized Use Only

WRAITH is intended strictly for:
- Authorized security assessments of domains and infrastructure you own or manage
- Defensive monitoring of your organization's digital footprint
- Security research in controlled lab environments

**Unauthorized use against systems, domains, or email addresses you do not own or have explicit written permission to monitor is strictly prohibited and may be illegal.**

---

## License

MIT © 2026 xdrew87

---

## FAQ

**Q: Which feeds require paid API keys?**  
HIBP requires a paid key for domain lookup (breacheddomain endpoint). DeHashed and IntelX are paid services. GitHub works free but rate limits are very low without a token. Pastebin scrape API requires a PRO account.

**Q: Can I use PostgreSQL instead of SQLite?**  
Yes. Set `DATABASE_URL=postgresql+psycopg2://user:pass@host/dbname` in your `.env` file.

**Q: How do I add the dashboard to a reverse proxy?**  
Set `--host 127.0.0.1` (default) and proxy from nginx/caddy. Set `DASHBOARD_ALLOWED_ORIGINS` to your public dashboard URL.

**Q: How often does the monitor daemon scan?**  
Configurable via `monitor.interval_seconds` in `config.yaml`. Default is 3600 seconds (1 hour).

---

## Troubleshooting

See [docs/Troubleshooting.md](docs/Troubleshooting.md) for common issues and solutions.
