"""Fire-and-forget webhook delivery for pack completion notifications.

The URL is supplied per request, so it is a server-side request forgery
primitive unless it is checked: without validation an authenticated caller can
point fuin at ``http://169.254.169.254/`` or any host inside the deployment
network and have the pack result POSTed there.
"""

import ipaddress
import logging
import os
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpx

from fuin.config import parse_env_bool
from fuin.server.background import spawn

log = logging.getLogger(__name__)

_ALLOWED_SCHEMES = frozenset({"https"})


def _plain_http_allowed() -> bool:
    """Whether ``http://`` webhooks are permitted.

    Off by default: the payload carries the package name and pack report.
    """
    return parse_env_bool(os.environ.get("FUIN_WEBHOOK_ALLOW_HTTP"))


def _resolves_to_a_public_address(host: str) -> bool:
    """Whether every address ``host`` resolves to is publicly routable.

    All of them, not just the first: a name that returns both a public and a
    loopback address would otherwise pass here and connect to the loopback.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        log.warning("webhook host %s does not resolve: %s", host, exc)
        return False

    if not infos:
        return False

    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            log.warning("refusing webhook to %s: %s is not a public address", host, address)
            return False
    return True


def is_safe_url(url: str) -> bool:
    """Whether ``url`` is a webhook target fuin is willing to call."""
    parts = urlsplit(url)
    allowed = _ALLOWED_SCHEMES | ({"http"} if _plain_http_allowed() else frozenset())
    if parts.scheme not in allowed:
        log.warning("refusing webhook to %s: scheme %r not allowed", url, parts.scheme)
        return False
    if not parts.hostname:
        return False
    return _resolves_to_a_public_address(parts.hostname)


def parse_urls(*sources: str) -> list[str]:
    """Split each comma-separated source and return non-empty unique URLs in order.

    Unsafe targets are dropped here rather than at POST time, so a rejected URL
    is never stored against the app either.
    """
    seen: set[str] = set()
    out: list[str] = []
    for s in sources:
        for raw in (s or "").split(","):
            url = raw.strip()
            if url and url not in seen:
                seen.add(url)
                if is_safe_url(url):
                    out.append(url)
    return out


async def _post(url: str, payload: dict, *, timeout: float = 10.0) -> None:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            await client.post(url, json=payload)
    except httpx.HTTPError as e:
        log.warning("webhook POST to %s failed: %s", url, e)


def fire(urls: Iterable[str], payload: dict) -> None:
    """Schedule POSTs to every URL without awaiting them."""
    for url in urls:
        spawn(_post(url, payload))
