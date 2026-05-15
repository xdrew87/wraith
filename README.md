# WRAITH

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-red)]()

**WRAITH** is a credential exposure monitoring tool for red teams and security researchers. It monitors paste sites and breach databases for exposed credentials tied to target domains — aggregating results from HIBP, DeHashed, IntelX, Pastebin, and GitHub, then alerting via Email, Slack, or Discord on new hits.

---

## Features

- 🔍 **Multi-source monitoring** — HIBP, DeHashed, IntelX, Pastebin, GitHub
- 🔗 **Domain-scoped targeting** — watch specific domains for credential exposure
- 🧠 **Correlation engine** — deduplicates and links findings across sources
- 📊 **Historical database** — SQLite (dev) / PostgreSQL (prod) via SQLAlchemy
- 🚨 **Real-time alerting** — Email (SMTP), Slack webhook, Discord webhook
- 🖥️ **Web dashboard** — dark theme SPA with findings table, source status, alert feed
- 📁 **Export** — JSON, CSV, rich terminal table output
- ⚙️ **Background monitoring** — daemon mode with configurable scan intervals

---

## Installation

```bash
git clone https://github.com/xdrew87/wraith.git
cd wraith
py -m pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
```

---

## Configuration

Edit `config.yaml` for defaults, or set environment variables to override.

| Key | Env Variable | Description |
|-----|-------------|-------------|
| `feeds.hibp.api_key` | `HIBP_API_KEY` | HaveIBeenPwned API key |
| `feeds.dehashed.email` | `DEHASHED_EMAIL` | DeHashed account email |
| `feeds.dehashed.api_key` | `DEHASHED_API_KEY` | DeHashed API key |
| `feeds.intelx.api_key` | `INTELX_API_KEY` | Intelligence X API key |
| `feeds.github.token` | `GITHUB_TOKEN` | GitHub personal access token |
| `database.url` | `DATABASE_URL` | SQLAlchemy DB URL (SQLite default) |
| `alerting.smtp.host` | `SMTP_HOST` | SMTP server host |
| `alerting.smtp.user` | `SMTP_USER` | SMTP username |
| `alerting.smtp.password` | `SMTP_PASSWORD` | SMTP password |
| `alerting.slack.webhook_url` | `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `alerting.discord.webhook_url` | `DISCORD_WEBHOOK_URL` | Discord webhook URL |

---

## Usage

```bash
# Initialize the database
py src/main.py init

# Scan a domain once
py src/main.py scan example.com

# Scan an email address
py src/main.py scan user@example.com

# Add domain to watch list (continuous monitoring)
py src/main.py watch example.com

# Remove from watch list
py src/main.py unwatch example.com

# Show recent findings
py src/main.py report --format table
py src/main.py report --format json --output results.json

# Show alerts
py src/main.py alerts

# Launch web dashboard
py src/main.py dashboard --port 5050
```

---

## Dashboard

```bash
py src/main.py dashboard --port 5050
# Open http://localhost:5050
```

Dashboard shows: live findings table, source status, alert feed, exposure stats.

---

## Output Example

```
Target: example.com
─────────────────────────────────────────────────────────
Source        Type       Value                  Severity
─────────────────────────────────────────────────────────
HIBP          Email      admin@example.com      HIGH
DeHashed      Password   p@ssw0rd123 (hash)     CRITICAL
IntelX        Paste      API key in paste       HIGH
GitHub        Secret     token in public repo   CRITICAL
Pastebin      Email      dev@example.com        MEDIUM
─────────────────────────────────────────────────────────
5 findings | 2 CRITICAL | 2 HIGH | 1 MEDIUM
```

---

## ⚠️ Authorized Use Only

WRAITH is intended strictly for:
- Authorized security assessments
- Defensive monitoring of domains you own or are authorized to test
- Security research in lab environments

**Unauthorized use against systems or domains you do not own or have explicit permission to monitor is strictly prohibited.**

---

## License

MIT © 2026 xdrew87
