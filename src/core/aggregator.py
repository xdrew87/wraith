import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from core.database import ExposedCredential, FeedStatus, db_session
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
            logger.debug("[%s] Does not support target type '%s' — skipping", feed_name, target_type)
            return []

        feed_cfg = config.get("feeds", {}).get(feed_name, {})
        if not feed_cfg.get("enabled", True):
            logger.debug("[%s] Disabled in config — skipping", feed_name)
            return []

        results = await feed.lookup(target, target_type)
        logger.info("[%s] %d result(s) for %s", feed_name, len(results), target)

    except Exception as e:
        status = "error"
        error = str(e)
        logger.error("[%s] Error during lookup: %s", feed_name, e)
    finally:
        await feed.close()
        _update_feed_status(feed_name, status, error, len(results))

    return results


def _update_feed_status(feed_name: str, status: str, error: Optional[str], result_count: int) -> None:
    try:
        with db_session() as db:
            row = db.query(FeedStatus).filter_by(feed_name=feed_name).first()
            if not row:
                row = FeedStatus(feed_name=feed_name, total_results=0)
                db.add(row)
            row.last_run_at = datetime.now(timezone.utc).replace(tzinfo=None)
            row.last_status = status
            row.last_error = error
            row.total_results = (row.total_results or 0) + result_count
            db.commit()
    except Exception as e:
        logger.warning("Could not update feed status for %s: %s", feed_name, e)


def save_results(results: list[dict]) -> tuple[int, int]:
    """Persist results to DB. Returns (new_count, duplicate_count)."""
    if not results:
        return 0, 0

    new_count = 0
    dupe_count = 0

    try:
        with db_session() as db:
            incoming_hashes = [r["hash"] for r in results]
            existing_hashes = {
                row[0]
                for row in db.query(ExposedCredential.hash)
                .filter(ExposedCredential.hash.in_(incoming_hashes))
                .all()
            }

            for result in results:
                if result["hash"] in existing_hashes:
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
                existing_hashes.add(result["hash"])
                new_count += 1

            db.commit()
    except Exception as e:
        logger.error("Error saving results to DB: %s", e)

    return new_count, dupe_count


async def aggregate(target: str, config: dict, feed_names: Optional[list[str]] = None) -> list[dict]:
    """Run all enabled feeds against a target and return all results."""
    target_type = detect_target_type(target)
    logger.info("Scanning target: %s (type: %s)", target, target_type)

    feeds_to_run = {
        name: cls for name, cls in FEED_CLASSES.items()
        if feed_names is None or name in feed_names
    }

    tasks = [
        run_feed(name, cls, config, target, target_type)
        for name, cls in feeds_to_run.items()
    ]

    all_results = []
    feed_results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in feed_results:
        if isinstance(result, Exception):
            logger.error("Feed task raised unhandled exception: %s", result)
            continue
        all_results.extend(result)

    new_count, dupe_count = save_results(all_results)
    logger.info(
        "Scan complete: %d total, %d new, %d duplicates",
        len(all_results), new_count, dupe_count,
    )

    return all_results
