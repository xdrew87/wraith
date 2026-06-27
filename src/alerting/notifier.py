import asyncio
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape as html_escape
from urllib.parse import urlparse

import aiohttp

from core.database import Alert, db_session

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_ALLOWED_WEBHOOK_SCHEMES = {"https"}
_ALLOWED_WEBHOOK_HOSTS = {
    "hooks.slack.com",
    "discord.com",
    "discordapp.com",
    "canary.discord.com",
}


def _validate_webhook_url(url: str) -> bool:
    """Prevent SSRF by allowing only known webhook hosts over HTTPS."""
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in _ALLOWED_WEBHOOK_SCHEMES
            and any(parsed.hostname.endswith(h) for h in _ALLOWED_WEBHOOK_HOSTS)
        )
    except Exception:
        return False


async def queue_alerts(target: str, results: list[dict], config: dict) -> None:
    """Queue alerts for new findings and dispatch them."""
    alert_cfg = config.get("alerting", {})
    if not alert_cfg.get("enabled", True):
        return

    min_severity = alert_cfg.get("min_severity", "MEDIUM")
    min_level = SEVERITY_ORDER.get(min_severity, 1)

    new_alerts = [
        r for r in results
        if SEVERITY_ORDER.get(r.get("severity", "LOW"), 0) >= min_level
    ]

    if not new_alerts:
        return

    try:
        with db_session() as db:
            for r in new_alerts:
                message = (
                    f"[{r['severity']}] {r['source_feed']}: {r['exposure_type']} — "
                    f"{(r['value'] or '')[:100]}"
                )
                alert = Alert(
                    target=target,
                    source_feed=r["source_feed"],
                    severity=r["severity"],
                    message=message,
                    sent=False,
                )
                db.add(alert)
            db.commit()
    except Exception as e:
        logger.error("Failed to persist alerts for %s: %s", target, e)

    await dispatch_alerts(new_alerts, target, config)


async def dispatch_alerts(results: list[dict], target: str, config: dict) -> None:
    alert_cfg = config.get("alerting", {})
    tasks = []

    slack_cfg = alert_cfg.get("slack", {})
    if slack_cfg.get("enabled"):
        webhook = slack_cfg.get("webhook_url", "")
        if _validate_webhook_url(webhook):
            tasks.append(_send_slack(results, target, webhook))
        else:
            logger.warning("Slack webhook URL failed validation — skipping")

    discord_cfg = alert_cfg.get("discord", {})
    if discord_cfg.get("enabled"):
        webhook = discord_cfg.get("webhook_url", "")
        if _validate_webhook_url(webhook):
            tasks.append(_send_discord(results, target, webhook))
        else:
            logger.warning("Discord webhook URL failed validation — skipping")

    if alert_cfg.get("smtp", {}).get("enabled"):
        tasks.append(_send_email_async(results, target, alert_cfg["smtp"]))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _send_slack(results: list[dict], target: str, webhook_url: str) -> None:
    critical = sum(1 for r in results if r.get("severity") == "CRITICAL")
    high = sum(1 for r in results if r.get("severity") == "HIGH")

    color = "danger" if critical > 0 else "warning"
    fields = [
        {"title": "Target", "value": target, "short": True},
        {"title": "Findings", "value": str(len(results)), "short": True},
        {"title": "Critical", "value": str(critical), "short": True},
        {"title": "High", "value": str(high), "short": True},
    ]

    for r in results[:5]:
        fields.append({
            "title": f"[{r['severity']}] {r['source_feed']}",
            "value": f"{r['exposure_type']}: {(r['value'] or '')[:80]}",
            "short": False,
        })

    payload = {
        "attachments": [{
            "color": color,
            "title": f"WRAITH Alert — {target}",
            "fields": fields,
            "footer": "WRAITH Credential Monitor",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, ssl=True) as resp:
                if resp.status != 200:
                    logger.error("Slack alert failed: HTTP %d", resp.status)
                else:
                    logger.info("Slack alert sent for %s", target)
    except Exception as e:
        logger.error("Slack alert error: %s", e)


async def _send_discord(results: list[dict], target: str, webhook_url: str) -> None:
    critical = sum(1 for r in results if r.get("severity") == "CRITICAL")
    color = 0xFF0000 if critical > 0 else 0xFF8800

    description_lines = []
    for r in results[:10]:
        value_safe = (r.get("value") or "")[:60]
        description_lines.append(
            f"**[{r['severity']}]** `{r['source_feed']}` — {r['exposure_type']}: `{value_safe}`"
        )

    embed = {
        "title": f"\U0001f6a8 WRAITH Alert — {target}",
        "description": "\n".join(description_lines),
        "color": color,
        "fields": [
            {"name": "Total Findings", "value": str(len(results)), "inline": True},
            {"name": "Critical", "value": str(critical), "inline": True},
        ],
        "footer": {"text": "WRAITH Credential Monitor"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload = {"embeds": [embed]}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, ssl=True) as resp:
                if resp.status not in (200, 204):
                    logger.error("Discord alert failed: HTTP %d", resp.status)
                else:
                    logger.info("Discord alert sent for %s", target)
    except Exception as e:
        logger.error("Discord alert error: %s", e)


async def _send_email_async(results: list[dict], target: str, smtp_cfg: dict) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_email_sync, results, target, smtp_cfg)


def _send_email_sync(results: list[dict], target: str, smtp_cfg: dict) -> None:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = (
            f"[WRAITH] Credential Exposure Alert — {target} ({len(results)} findings)"
        )
        msg["From"] = smtp_cfg.get("from_email", "")
        msg["To"] = smtp_cfg.get("to_email", "")

        rows = ""
        for r in results:
            sev = r.get("severity", "")
            color = "red" if sev in ("CRITICAL", "HIGH") else "orange"
            rows += (
                f"<tr>"
                f"<td>{html_escape(r.get('source_feed', ''))}</td>"
                f"<td>{html_escape(r.get('exposure_type', ''))}</td>"
                f"<td>{html_escape((r.get('value') or '')[:80])}</td>"
                f"<td style='color:{color}'>{html_escape(sev)}</td>"
                f"<td>{html_escape(r.get('breach_name', '') or '')}</td>"
                f"</tr>"
            )

        html = f"""
        <html><body>
        <h2>WRAITH Credential Exposure Alert</h2>
        <p><strong>Target:</strong> {html_escape(target)}</p>
        <p><strong>Findings:</strong> {len(results)}</p>
        <table border="1" cellpadding="5" cellspacing="0">
          <thead><tr><th>Source</th><th>Type</th><th>Value</th><th>Severity</th><th>Breach</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        <p style="font-size:11px;color:gray;">WRAITH Credential Monitor — Authorized use only</p>
        </body></html>
        """

        msg.attach(MIMEText(html, "html"))

        host = smtp_cfg.get("host", "")
        port = int(smtp_cfg.get("port", 587))
        use_tls = smtp_cfg.get("use_tls", True)
        user = smtp_cfg.get("user", "")
        password = smtp_cfg.get("password", "")

        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port) as server:
                server.ehlo()
                server.starttls(context=context)
                if user and password:
                    server.login(user, password)
                server.sendmail(msg["From"], msg["To"], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as server:
                if user and password:
                    server.login(user, password)
                server.sendmail(msg["From"], msg["To"], msg.as_string())

        logger.info("Email alert sent for %s", target)
    except Exception as e:
        logger.error("Email alert error: %s", e)
