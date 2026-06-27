import asyncio
import logging
from datetime import datetime, timezone

from alerting.notifier import queue_alerts
from core.aggregator import aggregate
from core.database import WatchTarget, db_session

logger = logging.getLogger(__name__)


async def monitor_loop(config: dict) -> None:
    """Continuously scan all active watch targets on the configured interval."""
    interval = config.get("monitor", {}).get("interval_seconds", 3600)
    logger.info("Monitor daemon started — scan interval: %ds", interval)

    while True:
        await run_scan_cycle(config)
        logger.info("Next scan in %ds", interval)
        await asyncio.sleep(interval)


async def run_scan_cycle(config: dict) -> None:
    """Run one full cycle — scan all active watch targets."""
    with db_session() as db:
        targets = db.query(WatchTarget).filter_by(active=True).all()
        # Copy data before session closes
        target_list = [(wt.id, wt.target) for wt in targets]

    if not target_list:
        logger.info("No active watch targets")
        return

    logger.info("Scanning %d watch target(s)", len(target_list))
    for wt_id, wt_target in target_list:
        try:
            results = await aggregate(wt_target, config)

            with db_session() as db:
                wt = db.query(WatchTarget).filter_by(id=wt_id).first()
                if wt:
                    wt.last_scanned_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    db.commit()

            await queue_alerts(wt_target, results, config)

        except Exception as e:
            logger.error("Error scanning %s: %s", wt_target, e)
