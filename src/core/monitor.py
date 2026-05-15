import asyncio
import logging
from datetime import datetime

from core.database import WatchTarget, Alert, get_db
from core.aggregator import aggregate

logger = logging.getLogger(__name__)


async def monitor_loop(config: dict) -> None:
    """Continuously scan all active watch targets on the configured interval."""
    interval = config.get("monitor", {}).get("interval_seconds", 3600)
    logger.info(f"Monitor daemon started — scan interval: {interval}s")

    while True:
        await run_scan_cycle(config)
        logger.info(f"Next scan in {interval}s")
        await asyncio.sleep(interval)


async def run_scan_cycle(config: dict) -> None:
    """Run one full cycle — scan all active watch targets."""
    db = get_db()
    try:
        targets = db.query(WatchTarget).filter_by(active=True).all()
        if not targets:
            logger.info("No active watch targets")
            return

        logger.info(f"Scanning {len(targets)} watch target(s)")
        for wt in targets:
            try:
                results = await aggregate(wt.target, config)
                wt.last_scanned_at = datetime.utcnow()
                db.commit()

                # Queue alerts for new findings
                from alerting.notifier import queue_alerts
                await queue_alerts(wt.target, results, config)

            except Exception as e:
                logger.error(f"Error scanning {wt.target}: {e}")
    finally:
        db.close()
