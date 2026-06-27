import logging
import re

from feeds.base import BaseFeed

logger = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# psbdmp.ws — public paste search, no account required
PSBDMP_SEARCH = "https://psbdmp.ws/api/v3/search/{query}"
PSBDMP_DUMP = "https://psbdmp.ws/dumps/{paste_id}"


class PastebinFeed(BaseFeed):
    """Paste intelligence — scans public pastes for domain/email matches.

    Primary: Pastebin scraping API (requires PRO account).
    Fallback: psbdmp.ws public paste search (no account required).
    """

    name = "Pastebin"
    supported_types = ["domain", "email"]

    def __init__(self, config: dict):
        super().__init__(config)
        feed_cfg = config.get("feeds", {}).get("pastebin", {})
        self.scrape_url = feed_cfg.get("scrape_url", "https://scrape.pastebin.com/api_scraping.php")
        self.fetch_url = feed_cfg.get("fetch_url", "https://scrape.pastebin.com/api_scrape_item.php")
        self.limit = feed_cfg.get("limit", 100)
        self._pro_available: bool | None = None  # lazily determined on first call

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        # Try Pastebin PRO scrape API first; fall back to psbdmp.ws
        if self._pro_available is not False:
            pastes = await self._get_recent_pastes()
            if pastes:
                self._pro_available = True
                return await self._scan_pastes(target, target_type, pastes)
            self._pro_available = False

        return await self._psbdmp_search(target, target_type)

    # ------------------------------------------------------------------ #
    # Pastebin PRO scrape API
    # ------------------------------------------------------------------ #

    async def _get_recent_pastes(self) -> list[dict]:
        data = await self._get(self.scrape_url, params={"limit": self.limit})
        if isinstance(data, list):
            return data
        text = data.get("_text", "")
        if "DOES NOT HAVE ACCESS" in text or "NOT ALLOWED" in text:
            logger.warning("[Pastebin] Scrape API requires PRO account — switching to psbdmp.ws")
            self._skip_reason = "PRO account required"
            return []
        return []

    async def _scan_pastes(self, target: str, target_type: str, pastes: list[dict]) -> list[dict]:
        results = []
        for paste in pastes:
            paste_key = paste.get("key", "")
            paste_title = paste.get("title", "")
            content = await self._fetch_paste(paste_key)
            if not content:
                continue
            for hit_value in self._scan_content(content, target, target_type):
                results.append(self._make_paste_result(target, paste_key, paste_title, hit_value, "pastebin.com"))
        return results

    async def _fetch_paste(self, paste_key: str) -> str:
        data = await self._get(self.fetch_url, params={"i": paste_key})
        return data.get("_text", "")

    # ------------------------------------------------------------------ #
    # psbdmp.ws fallback (no account required)
    # ------------------------------------------------------------------ #

    async def _psbdmp_search(self, target: str, target_type: str) -> list[dict]:
        url = PSBDMP_SEARCH.format(query=target)
        data = await self._get(url, headers={"Accept": "application/json"})

        paste_ids: list[str] = []
        if isinstance(data, dict):
            paste_ids = [entry["id"] for entry in data.get("data", []) if entry.get("id")]
        elif isinstance(data, list):
            paste_ids = [entry["id"] for entry in data if entry.get("id")]

        if not paste_ids:
            return []

        results = []
        for paste_id in paste_ids[:20]:  # cap to avoid excessive requests
            content_data = await self._get(PSBDMP_DUMP.format(paste_id=paste_id))
            content = content_data.get("_text", "")
            if not content:
                continue
            for hit_value in self._scan_content(content, target, target_type):
                results.append(self._make_paste_result(target, paste_id, "", hit_value, "psbdmp.ws"))

        return results

    # ------------------------------------------------------------------ #
    # Shared helpers
    # ------------------------------------------------------------------ #

    def _make_paste_result(self, target: str, paste_id: str, paste_title: str, hit_value: str, source: str) -> dict:
        exposure_type = "paste_email" if "@" in hit_value else "paste_domain_hit"
        label = f"'{paste_title}' " if paste_title else ""
        url = f"https://{source}/{paste_id}"
        return self.make_result(
            target=target,
            source_feed=self.name,
            exposure_type=exposure_type,
            value=hit_value,
            severity="HIGH",
            breach_name=f"paste:{source}:{paste_id}",
            description=f"Match found in paste {label}({url})",
            raw={"id": paste_id, "title": paste_title, "hit": hit_value, "source": source},
        )

    def _scan_content(self, content: str, target: str, target_type: str) -> list[str]:
        hits: set[str] = set()
        content_lower = content.lower()

        if target_type == "domain":
            if target.lower() in content_lower:
                for email in EMAIL_RE.findall(content):
                    if target.lower() in email.lower():
                        hits.add(email)
                if not hits:
                    hits.add(target)
        elif target_type == "email" and target.lower() in content_lower:
            hits.add(target)

        return list(hits)
