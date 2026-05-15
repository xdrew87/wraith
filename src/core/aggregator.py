import asyncio
import logging
from typing import Optional

from core.database import ExposedCredential, FeedStatus, get_db
from feeds.hibp import HIBPFeed
from feeds.dehashed import DeHashedFeed
from feeds.intelx import IntelXFeed
from feeds.pastebin import PastebinFeed
from feeds.github import GitHubFeed

logger = logging.getLogger(__name__)

FEED_CLASSES = {
    "hibp": HIBPFeed,
    "dehashed": DeHashedFeed,
    "intelx": IntelXFeed,
    "pastebin": PastebinFeed,
    "github": GitHubFeed,
}


def detect_target_type(target: str) -> str:
    if "@" in target:
        return "email"
    return "domain"


async def run_feed(feed_name: str, feed_class, config: dict, target: str, target_type: str) -> list[dict]:
    feed = feed_class(config)
    results = []
    status = "ok"
    error = None

    try:
        if not feed.supports(target_type):
            logger.debug(f"[{feed_name}] Does not support target type '{target_type}' — skipping")
            return []

        feed_cfg = config.get("feeds", {}).get(feed_name, {})
        if not feed_cfg.get("enabled", True):
            logger.debug(f"[{feed_name}] Disabled in config — skipping")
            return []

        results = await feed.lookup(target, target_type)
        logger.info(f"[{feed_name}] {len(results)} result(s) for {target}")

    except Exception as e:
        status = "error"
        error = str(e)
        logger.error(f"[{feed_name}] Error during lookup: {e}")
    finally:
        await feed.close()
        _update_feed_status(feed_name, status, error, len(results))

    return results


def _update_feed_status(feed_name: str, status: str, error: Optional[str], result_count: int) -> None:
    from datetime import datetime
    try:
        db = get_db()
        row = db.query(FeedStatus).filter_by(feed_name=feed_name).first()
        if not row:
            row = FeedStatus(feed_name=feed_name, total_results=0)
            db.add(row)
        row.last_run_at = datetime.utcnow()
        row.last_status = status
        row.last_error = error
        row.total_results = (row.total_results or 0) + result_count
        db.commit()
        db.close()
    except Exception as e:
        logger.warning(f"Could not update feed status for {feed_name}: {e}")


def save_results(results: list[dict]) -> tuple[int, int]:
    """Persist results to DB. Returns (new_count, duplicate_count)."""
    new_count = 0
    dupe_count = 0

    try:
        db = get_db()
        for result in results:
            existing = db.query(ExposedCredential).filter_by(hash=result["hash"]).first()
            if existing:
                dupe_count += 1
                continue

            cred = ExposedCredential(
                target=result["target"],
                source_feed=result["source_feed"],
                exposure_type=result["exposure_type"],
                value=result["value"],
                severity=result["severity"],
                breach_name=result.get("breach_name"),
                breach_date=result.get("breach_date"),
                description=result.get("description"),
                raw=result.get("raw"),
                hash=result["hash"],
            )
            db.add(cred)
            new_count += 1

        db.commit()
        db.close()
    except Exception as e:
        logger.error(f"Error saving results to DB: {e}")

    return new_count, dupe_count


async def aggregate(target: str, config: dict, feed_names: Optional[list[str]] = None) -> list[dict]:
    """Run all enabled feeds against a target and return all results."""
    target_type = detect_target_type(target)
    logger.info(f"Scanning target: {target} (type: {target_type})")

    feeds_to_run = {
        name: cls for name, cls in FEED_CLASSES.items()
        if feed_names is None or name in feed_names
    }

    tasks = [
        run_feed(name, cls, config, target, target_type)
        for name, cls in feeds_to_run.items()
    ]

    all_results = []
    feed_results = await asyncio.gather(*tasks, return_exceptions=False)
    for results in feed_results:
        all_results.extend(results)

    new_count, dupe_count = save_results(all_results)
    logger.info(f"Scan complete: {len(all_results)} total, {new_count} new, {dupe_count} duplicates")

    return all_results
