# WRAITH — Configuration Reference

## Configuration Hierarchy

Configuration is loaded in this order (later sources override earlier):

1. `config.yaml` (file defaults)
2. Environment variables (from `.env` or system environment)

---

## Full config.yaml Reference

```yaml
database:
  url: ""              # Set to a SQLAlchemy URL for PostgreSQL. Leave blank for SQLite.
  sqlite_path: "wraith.db"  # Path to SQLite file (ignored when url is set)

feeds:
  hibp:
    enabled: true
    api_key: ""        # Required. Set via HIBP_API_KEY env var.
    base_url: "https://haveibeenpwned.com/api/v3"
    rate_limit: 1      # Requests per second (HIBP free tier: 1 RPS)

  dehashed:
    enabled: true
    email: ""          # DeHashed account email. Set via DEHASHED_EMAIL.
    api_key: ""        # Set via DEHASHED_API_KEY.
    base_url: "https://api.dehashed.com"

  intelx:
    enabled: true
    api_key: ""        # Set via INTELX_API_KEY.
    base_url: "https://2.intelx.io"

  pastebin:
    enabled: true
    scrape_url: "https://scrape.pastebin.com/api_scraping.php"
    fetch_url: "https://scrape.pastebin.com/api_scrape_item.php"
    limit: 100         # Number of recent pastes to check per scan

  github:
    enabled: true
    token: ""          # Personal access token. Set via GITHUB_TOKEN.
    base_url: "https://api.github.com"
    rate_limit: 10     # GitHub code search: 10 requests/minute (authenticated)

monitor:
  interval_seconds: 3600  # How often the daemon re-scans all watch targets (seconds)
  max_concurrent_feeds: 5 # Maximum concurrent feed requests per scan

alerting:
  enabled: true
  min_severity: "MEDIUM"  # Minimum severity to trigger alerts: LOW|MEDIUM|HIGH|CRITICAL

  smtp:
    enabled: false
    host: ""           # SMTP server hostname. Set via SMTP_HOST.
    port: 587          # SMTP port. Set via SMTP_PORT.
    user: ""           # Set via SMTP_USER.
    password: ""       # Set via SMTP_PASSWORD.
    from_email: ""     # Set via ALERT_FROM_EMAIL.
    to_email: ""       # Set via ALERT_TO_EMAIL.
    use_tls: true      # Enable STARTTLS

  slack:
    enabled: false
    webhook_url: ""    # Slack incoming webhook. Set via SLACK_WEBHOOK_URL.

  discord:
    enabled: false
    webhook_url: ""    # Discord webhook. Set via DISCORD_WEBHOOK_URL.

logging:
  level: "INFO"         # DEBUG | INFO | WARNING | ERROR | CRITICAL
  file: "logs/wraith.log"
  max_bytes: 10485760   # 10 MB per log file before rotation
  backup_count: 5       # Number of rotated log files to keep
```

---

## Environment Variable Reference

See the main [README](../README.md#environment-variables) for the full table.

## Per-Feed Configuration

### HIBP
- Free API key available at [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)
- Domain search (`breacheddomain`) requires an enterprise key
- Rate limit: 1 request/second on free tier

### DeHashed
- Paid service — [dehashed.com](https://dehashed.com)
- Requires both `email` (account email) and `api_key`
- Returns plaintext passwords, hashed passwords, and email exposures

### Intelligence X
- Paid service — [intelx.io](https://intelx.io)
- Returns paste and leak hits
- Free tier available with limited results

### Pastebin
- Requires Pastebin PRO account for the scrape API
- Without PRO, the feed is gracefully skipped

### GitHub
- Works without a token but rate-limited to 10 requests/hour unauthenticated
- Create a token at [github.com/settings/tokens](https://github.com/settings/tokens) with `public_repo` read scope
- Searches public repositories for domain/email mentions and credential patterns
