import asyncio
import hashlib
import json
import logging

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 2.0


class BaseFeed:
    """Abstract base class for all credential exposure feed integrations."""

    name: str = "base"
    supported_types: list[str] = []  # e.g. ["domain", "email"]

    def __init__(self, config: dict):
        self.config = config
        self._session: aiohttp.ClientSession | None = None
        self._semaphore = asyncio.Semaphore(config.get("monitor", {}).get("max_concurrent_feeds", 5))
        self._skip_reason: str | None = None  # set before returning [] to signal a skip vs. no results

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=True)
            self._session = aiohttp.ClientSession(
                timeout=DEFAULT_TIMEOUT,
                connector=connector,
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _get(self, url: str, headers: dict = None, params: dict = None) -> dict:
        return await self._request("GET", url, headers=headers, params=params)

    async def _post(self, url: str, headers: dict = None, json_data: dict = None) -> dict:
        return await self._request("POST", url, headers=headers, json_data=json_data)

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        params: dict = None,
        json_data: dict = None,
        retries: int = DEFAULT_RETRIES,
    ) -> dict:
        session = await self._get_session()
        attempt = 0
        last_error = None

        async with self._semaphore:
            while attempt < retries:
                try:
                    async with session.request(method, url, headers=headers, params=params, json=json_data) as resp:
                        if resp.status == 429:
                            retry_after = float(resp.headers.get("Retry-After", DEFAULT_BACKOFF * (attempt + 1)))
                            logger.warning("[%s] Rate limited. Waiting %.1fs", self.name, retry_after)
                            await asyncio.sleep(retry_after)
                            attempt += 1
                            continue

                        if resp.status == 404:
                            return {}

                        if resp.status >= 400:
                            text = await resp.text()
                            if resp.status >= 500:
                                logger.warning("[%s] HTTP %d (upstream error): %s", self.name, resp.status, text[:200])
                            else:
                                logger.warning("[%s] HTTP %d: %s", self.name, resp.status, text[:200])
                            return {}

                        content_type = resp.content_type or ""
                        if "json" in content_type:
                            return await resp.json()
                        return {"_text": await resp.text()}

                except asyncio.TimeoutError:
                    last_error = "Timeout"
                    logger.warning("[%s] Timeout on attempt %d", self.name, attempt + 1)
                except aiohttp.ClientConnectorDNSError as e:
                    # DNS failures are permanent — no point retrying
                    logger.warning("[%s] DNS resolution failed: %s", self.name, e)
                    return {}
                except aiohttp.ClientError as e:
                    last_error = str(e)
                    logger.warning("[%s] Client error on attempt %d: %s", self.name, attempt + 1, e)

                attempt += 1
                await asyncio.sleep(DEFAULT_BACKOFF * attempt)

        logger.error("[%s] All %d attempts failed. Last error: %s", self.name, retries, last_error)
        return {}

    def make_result(
        self,
        target: str,
        source_feed: str,
        exposure_type: str,
        value: str,
        severity: str,
        breach_name: str = None,
        breach_date: str = None,
        description: str = None,
        raw: dict = None,
    ) -> dict:
        raw_str = json.dumps(raw or {}, default=str)
        fingerprint = f"{target}:{source_feed}:{exposure_type}:{value}"
        result_hash = hashlib.sha256(fingerprint.encode()).hexdigest()

        return {
            "target": target,
            "source_feed": source_feed,
            "exposure_type": exposure_type,
            "value": value,
            "severity": severity,
            "breach_name": breach_name,
            "breach_date": breach_date,
            "description": description,
            "raw": raw_str,
            "hash": result_hash,
        }

    async def lookup(self, target: str, target_type: str) -> list[dict]:
        """Lookup credential exposures for a target. Must be implemented by subclasses."""
        raise NotImplementedError(f"{self.__class__.__name__} must implement lookup()")

    def supports(self, target_type: str) -> bool:
        return target_type in self.supported_types
