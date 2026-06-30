"""Fire-and-forget webhook delivery for pack completion notifications."""

import asyncio
import logging
from collections.abc import Iterable

import httpx

log = logging.getLogger(__name__)


def parse_urls(*sources: str) -> list[str]:
    """Split each comma-separated source and return non-empty unique URLs in order."""
    seen: set[str] = set()
    out: list[str] = []
    for s in sources:
        for raw in (s or "").split(","):
            url = raw.strip()
            if url and url not in seen:
                seen.add(url)
                out.append(url)
    return out


async def _post(url: str, payload: dict, *, timeout: float = 10.0) -> None:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            await client.post(url, json=payload)
    except Exception as e:
        log.warning("webhook POST to %s failed: %s", url, e)


def fire(urls: Iterable[str], payload: dict) -> None:
    """Schedule POSTs to every URL without awaiting them."""
    for url in urls:
        asyncio.create_task(_post(url, payload))
