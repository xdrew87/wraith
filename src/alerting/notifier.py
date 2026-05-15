import asyncio
import logging
import smtplib
import ssl
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiohttp

from core.database import Alert, get_db

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


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

    db = get_db()
    try:
        for r in new_alerts:
            message = (
                f"[{r['severity']}] {r['source_feed']}: {r['exposure_type']} — "
                f"{r['value'][:100]}"
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
    finally:
        db.close()

    await dispatch_alerts(new_alerts, target, config)


async def dispatch_alerts(results: list[dict], target: str, config: dict) -> None:
    alert_cfg = config.get("alerting", {})
    tasks = []

    if alert_cfg.get("slack", {}).get("enabled"):
        tasks.append(_send_slack(results, target, alert_cfg["slack"]["webhook_url"]))

    if alert_cfg.get("discord", {}).get("enabled"):
        tasks.append(_send_discord(results, target, alert_cfg["discord"]["webhook_url"]))

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
            "value": f"{r['exposure_type']}: {r['value'][:80]}",
            "short": False,
        })

    payload = {
        "attachments": [{
            "color": color,
            "title": f"WRAITH Alert — {target}",
            "fields": fields,
            "footer": "WRAITH Credential Monitor",
            "ts": int(datetime.utcnow().timestamp()),
        }]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as resp:
                if resp.status != 200:
                    logger.error(f"Slack alert failed: HTTP {resp.status}")
                else:
                    logger.info(f"Slack alert sent for {target}")
    except Exception as e:
        logger.error(f"Slack alert error: {e}")


async def _send_discord(results: list[dict], target: str, webhook_url: str) -> None:
    critical = sum(1 for r in results if r.get("severity") == "CRITICAL")
    color = 0xFF0000 if critical > 0 else 0xFF8800

    description_lines = []
    for r in results[:10]:
        description_lines.append(
            f"**[{r['severity']}]** `{r['source_feed']}` — {r['exposure_type']}: `{r['value'][:60]}`"
        )

    embed = {
        "title": f"🚨 WRAITH Alert — {target}",
        "description": "\n".join(description_lines),
        "color": color,
        "fields": [
            {"name": "Total Findings", "value": str(len(results)), "inline": True},
            {"name": "Critical", "value": str(critical), "inline": True},
        ],
        "footer": {"text": "WRAITH Credential Monitor"},
        "timestamp": datetime.utcnow().isoformat(),
    }

    payload = {"embeds": [embed]}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload) as resp:
                if resp.status not in (200, 204):
                    logger.error(f"Discord alert failed: HTTP {resp.status}")
                else:
                    logger.info(f"Discord alert sent for {target}")
    except Exception as e:
        logger.error(f"Discord alert error: {e}")


async def _send_email_async(results: list[dict], target: str, smtp_cfg: dict) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_email_sync, results, target, smtp_cfg)


def _send_email_sync(results: list[dict], target: str, smtp_cfg: dict) -> None:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[WRAITH] Credential Exposure Alert — {target} ({len(results)} findings)"
        msg["From"] = smtp_cfg.get("from_email", "")
        msg["To"] = smtp_cfg.get("to_email", "")

        rows = ""
        for r in results:
            rows += (
                f"<tr>"
                f"<td>{r.get('source_feed','')}</td>"
                f"<td>{r.get('exposure_type','')}</td>"
                f"<td>{r.get('value','')[:80]}</td>"
                f"<td style='color:{'red' if r.get('severity') in ('CRITICAL','HIGH') else 'orange'}'>"
                f"{r.get('severity','')}</td>"
                f"<td>{r.get('breach_name','') or ''}</td>"
                f"</tr>"
            )

        html = f"""
        <html><body>
        <h2>WRAITH Credential Exposure Alert</h2>
        <p><strong>Target:</strong> {target}</p>
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

        logger.info(f"Email alert sent for {target}")
    except Exception as e:
        logger.error(f"Email alert error: {e}")
