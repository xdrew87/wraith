# WRAITH — Integrations Guide

## Intelligence Feed Integrations

### HaveIBeenPwned (HIBP)

**API Version:** v3  
**Docs:** https://haveibeenpwned.com/API/v3

WRAITH uses two HIBP endpoints:
- `/breachedaccount/{email}` — for email targets: returns all breach records
- `/breacheddomain/{domain}` — for domain targets: returns all email/breach pairs (requires enterprise key)

Severity classification from HIBP `DataClasses`:
- **CRITICAL**: Passwords, Password Hints, Credit Cards, Private Keys
- **HIGH**: Email Addresses, Phone Numbers, Usernames, Social Security Numbers, Physical Addresses
- **MEDIUM**: Everything else

### DeHashed

**API Version:** v1  
**Docs:** https://www.dehashed.com/docs

Searches the DeHashed database by `email:<value>` or `domain:<value>`. Returns up to 100 entries per search.

Result types:
- `plaintext_password` → CRITICAL
- `hashed_password` → HIGH
- `email_exposure` → MEDIUM

### Intelligence X

**Docs:** https://intelx.io/docs

Uses a two-step search:
1. `POST /intelligent/search` — initiate search, returns `search_id`
2. `GET /intelligent/search/result?id=<search_id>` — fetch results after 3-second delay

Severity based on bucket:
- `pastes`, `leaks.private` → HIGH
- `leaks.public` → MEDIUM
- Other → LOW

### Pastebin

**Docs:** https://pastebin.com/doc_scraping_api

Fetches recent public pastes (requires PRO account) and scans content for:
- Email addresses matching the target domain → `paste_email` (HIGH)
- Domain mentions → `paste_domain_hit` (HIGH)

If no PRO account is configured, the feed is silently skipped.

### GitHub Code Search

**API Version:** 2022-11-28  
**Docs:** https://docs.github.com/en/rest/search

Searches public repositories for code containing the target domain/email. For each matching file, downloads content and scans for credential patterns:

| Pattern | Type | Severity |
|---|---|---|
| `ghp_...` | GitHub personal access token | CRITICAL |
| `AKIA...` | AWS access key ID | CRITICAL |
| `-----BEGIN ... PRIVATE KEY-----` | Private key | CRITICAL |
| `api_key = ...` | Generic API key | HIGH |
| `secret = ...` | Generic secret | HIGH |
| `token = ...` | Generic token | HIGH |
| `password = ...` | Password | HIGH |
| No secret found | Code mention | LOW |

---

## Alert Channel Integrations

### Slack

Configure an incoming webhook at `api.slack.com/messaging/webhooks`.

WRAITH sends structured attachment payloads with:
- Alert color (red for CRITICAL, warning for HIGH)
- Target and finding counts
- Up to 5 individual finding details

Webhook URL is validated against `hooks.slack.com` before dispatch (SSRF protection).

### Discord

Configure a webhook in your server's channel settings.

WRAITH sends an embed with severity color coding and a description of up to 10 findings.

Webhook URL is validated against `discord.com` / `discordapp.com` before dispatch.

### Email (SMTP)

Sends HTML-formatted emails with a findings table. Uses STARTTLS by default on port 587.

All values in the email body are HTML-escaped to prevent injection.

---

## Future Integrations

The following are planned for future releases:

- **MISP** — Export findings as MISP events/attributes
- **TheHive** — Create TheHive cases from high-severity clusters
- **OpenCTI** — Push IOCs to an OpenCTI instance
- **LeakIX** — Additional breach intelligence source
- **Breachsense** — Additional breach data provider
- **PagerDuty / OpsGenie** — On-call alerting
