import os
import logging
import logging.handlers
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

ENV_OVERRIDES = {
    "database.url": "DATABASE_URL",
    "feeds.hibp.api_key": "HIBP_API_KEY",
    "feeds.dehashed.email": "DEHASHED_EMAIL",
    "feeds.dehashed.api_key": "DEHASHED_API_KEY",
    "feeds.intelx.api_key": "INTELX_API_KEY",
    "feeds.github.token": "GITHUB_TOKEN",
    "alerting.smtp.host": "SMTP_HOST",
    "alerting.smtp.port": "SMTP_PORT",
    "alerting.smtp.user": "SMTP_USER",
    "alerting.smtp.password": "SMTP_PASSWORD",
    "alerting.smtp.from_email": "ALERT_FROM_EMAIL",
    "alerting.smtp.to_email": "ALERT_TO_EMAIL",
    "alerting.slack.webhook_url": "SLACK_WEBHOOK_URL",
    "alerting.discord.webhook_url": "DISCORD_WEBHOOK_URL",
}


def _set_nested(d: dict, key_path: str, value: Any) -> None:
    keys = key_path.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _get_nested(d: dict, key_path: str, default: Any = None) -> Any:
    keys = key_path.split(".")
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
    return d


def load_config(config_path: str = None) -> dict:
    if config_path is None:
        config_path = Path(__file__).resolve().parents[2] / "config.yaml"

    with open(config_path, "r") as f:
        config = yaml.safe_load(f) or {}

    for key_path, env_var in ENV_OVERRIDES.items():
        value = os.getenv(env_var)
        if value:
            _set_nested(config, key_path, value)

    return config


def setup_logging(config: dict) -> None:
    log_cfg = config.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    log_file = log_cfg.get("file", "logs/wraith.log")
    max_bytes = log_cfg.get("max_bytes", 10 * 1024 * 1024)
    backup_count = log_cfg.get("backup_count", 5)

    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    root = logging.getLogger()
    root.setLevel(level)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    rotating = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    rotating.setFormatter(formatter)
    root.addHandler(rotating)
