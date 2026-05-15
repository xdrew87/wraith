import asyncio
import logging

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)


class IntelXFeed(BaseFeed):
    """Intelligence X API — search breach/paste data by domain or email."""

    name = "IntelX"
    supported_types = ["email", "domain"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("intelx", {})
        self.api_key = feed_cfg.get("api_key", "")
        self.base_url = feed_cfg.get("base_url", "https://2.intelx.io")

    def _headers(self) -> dict:
        return {
            "x-key": self.api_key,
            "User-Agent": "WRAITH-CredMonitor/1.0",
        }

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        if not self.api_key:
            logger.warning("[IntelX] No API key configured — skipping")
            return []

        search_id = await self._start_search(target)
        if not search_id:
            return []

        await asyncio.sleep(3)
        return await self._fetch_results(target, search_id)

    async def _start_search(self, target: str) -> str:
        url = f"{self.base_url}/intelligent/search"
        payload = {
            "term": target,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 100,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": [],
        }
        data = await self._post(url, headers=self._headers(), json_data=payload)
        return data.get("id", "")

    async def _fetch_results(self, target: str, search_id: str) -> list[dict]:
        url = f"{self.base_url}/intelligent/search/result"
        params = {"id": search_id, "limit": 100, "offset": 0}
        data = await self._get(url, headers=self._headers(), params=params)

        results = []
        records = data.get("records") or []
        for record in records:
            system_id = record.get("systemid", "")
            bucket = record.get("bucket", "")
            record_name = record.get("name", "")
            date = record.get("date", "")

            # Determine severity based on bucket type
            if bucket in ("pastes", "leaks.private"):
                severity = "HIGH"
            elif bucket == "leaks.public":
                severity = "MEDIUM"
            else:
                severity = "LOW"

            results.append(self.make_result(
                target=target,
                source_feed=self.name,
                exposure_type="paste_hit",
                value=record_name or system_id,
                severity=severity,
                breach_name=bucket,
                breach_date=date[:10] if date else None,
                description=f"Found in IntelX bucket: {bucket} — {record_name}",
                raw=record,
            ))

        return results
