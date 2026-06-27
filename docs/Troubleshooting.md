# WRAITH — Troubleshooting

## Common Issues

---

### Database not initialized

**Error:** `RuntimeError: Database not initialized. Call init_db() first.`

**Fix:** Run `py src/main.py init` before using any other command.

---

### Feed skipped — no API key

**Log:** `[HIBP] No API key configured — skipping`

**Fix:** Set the relevant API key in your `.env` file. Example:
```
HIBP_API_KEY=your_api_key_here
```

---

### Pastebin returns no results

**Log:** `[Pastebin] Scrape API requires PRO account`

**Explanation:** Pastebin's scraping API requires a paid PRO account. Without it, the feed is gracefully skipped. This is expected behavior.

---

### Rate limit errors (429)

**Log:** `[HIBP] Rate limited. Waiting 2.0s`

**Explanation:** The feed automatically retries with back-off after receiving a 429 response. No action needed. If this happens frequently, reduce scan frequency by increasing `monitor.interval_seconds`.

---

### Dashboard not accessible

**Symptom:** Browser can't connect to `http://localhost:5050`

**Check 1:** Confirm the dashboard is running:
```bash
py src/main.py dashboard --port 5050
```

**Check 2:** Check the port isn't in use:
```bash
netstat -an | grep 5050
```

**Check 3:** If running in Docker, verify port mapping:
```bash
docker compose ps
```

---

### CORS errors in browser

**Error:** `Access to fetch at '...' from origin '...' has been blocked by CORS policy`

**Fix:** Set `DASHBOARD_ALLOWED_ORIGINS` to match the origin your browser is using:
```
DASHBOARD_ALLOWED_ORIGINS=http://localhost:5050,https://wraith.internal.example.com
```

---

### Duplicate findings not being deduplicated

**Explanation:** Deduplication is by SHA-256 of `{target}:{source_feed}:{exposure_type}:{value}`. If the same credential appears with a different value (e.g., truncated differently), it will create a new record. This is by design.

---

### Email alerts not sending

1. Verify SMTP settings in `.env`:
   ```
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=you@gmail.com
   SMTP_PASSWORD=app_password
   ALERT_FROM_EMAIL=you@gmail.com
   ALERT_TO_EMAIL=soc@yourcompany.com
   ```
2. For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833), not your account password.
3. Check `logs/wraith.log` for `Email alert error:` entries.

---

### Webhook alerts not sending

1. Verify the webhook URL is set and enabled in config:
   ```yaml
   alerting:
     slack:
       enabled: true
       webhook_url: "https://hooks.slack.com/services/..."
   ```
2. WRAITH validates webhook URLs against an allowlist. Only `hooks.slack.com` and `discord.com`/`discordapp.com` are allowed.
3. Test the webhook manually with curl:
   ```bash
   curl -X POST -H "Content-Type: application/json" \
     -d '{"text":"WRAITH test"}' \
     https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```

---

### GitHub feed returns only mentions, no secrets

**Explanation:** This is expected. WRAITH records every GitHub code match. If the file content doesn't contain a recognized credential pattern, the finding is recorded as `code_mention` with LOW severity. Only files containing patterns like `ghp_...`, `AKIA...`, or `-----BEGIN PRIVATE KEY-----` will produce HIGH/CRITICAL findings.

---

### Import errors when running tests

**Error:** `ModuleNotFoundError: No module named 'core'`

**Fix:** Tests must be run from the project root using `pytest`:
```bash
cd wraith
pytest tests/ -v
```

The `conftest.py` at the root adds `src/` to `sys.path` automatically.

---

### SQLite locked errors under load

**Explanation:** SQLite WAL mode (enabled automatically) allows one writer and multiple readers. Under very high concurrency, you may see locking errors. Switch to PostgreSQL for production deployments with multiple processes.

---

## Log Files

WRAITH writes logs to `logs/wraith.log` with automatic rotation (10 MB per file, 5 backups).

Log level can be set in `config.yaml`:
```yaml
logging:
  level: "DEBUG"  # Set to DEBUG for verbose feed output
```

---

## Getting Help

- Open an issue: https://github.com/xdrew87/wraith/issues
- Review logs: `logs/wraith.log`
- Run with debug logging: set `logging.level: "DEBUG"` in `config.yaml`
