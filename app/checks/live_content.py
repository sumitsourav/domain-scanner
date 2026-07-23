"""Live page content: fetch the domain's current site (if any) and scan it
for the same risk lexicon used against Wayback history, plus parking-page
detection. Wayback only tells you what a domain *used to* show — this is
the only check in the app that looks at what's there right now.

SSRF guard: the domain being scanned is fully attacker-controlled input (it
just has to resolve), so before fetching anything we resolve it ourselves
and refuse to connect if the IP is private/loopback/link-local/reserved.
Without this, a malicious domain could point at 127.0.0.1 or an internal
RFC1918 address and use this scanner to probe its own host or network.

Caveat: this is a check-then-fetch guard, not a fully DNS-rebinding-proof
one — httpx does its own independent resolution when it connects a moment
later, so a sufficiently active attacker flipping DNS answers between our
check and httpx's connect could theoretically slip through. Pinning the
actual connection to the IP we validated would close that gap but needs a
custom transport/resolver; not done here. Fine for a local/trusted-network
tool, worth hardening before any public deployment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any
from urllib.parse import unquote

import dns.asyncresolver
import httpx

from ..risk_lexicon import PATTERNS

TIMEOUT = 10.0
MAX_CHARS = 300_000  # cap how much decoded text we scan, not just download
MAX_REDIRECTS = 5

PARKING_SIGNATURES = [
    r"this domain (?:is|may be) for sale",
    r"buy this domain",
    r"domain (?:name )?is parked",
    r"future home of (?:something|.*your)",
    r"this web page is parked",
    r"related searches",  # common on ad-monetized parking pages
    r"the sponsored listings displayed above are served",
    r"godaddy.{0,40}(coming soon|parked)",
]
_PARKING_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PARKING_SIGNATURES]


async def _resolve_ip(domain: str) -> str | None:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 6.0
    try:
        answer = await resolver.resolve(domain, "A")
        return str(answer[0])
    except Exception:
        return None


async def _cancel(task: "asyncio.Task") -> None:
    """Cancel a pending request task and swallow its result/error, so it can't
    surface as an 'exception never retrieved' warning."""
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, httpx.HTTPError):
        pass


def _is_safe_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _scan_text(text: str) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for cat, pattern in PATTERNS.items():
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 30)
            snippet = text[start:m.end() + 30].strip()
            hits[cat] = [snippet]
    return hits


def _extract_title(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    title = re.sub(r"\s+", " ", unquote(m.group(1))).strip()
    return title[:200] if title else None


def _looks_parked(html: str, title: str | None) -> bool:
    haystack = (title or "") + " " + html[:20_000]
    return any(p.search(haystack) for p in _PARKING_PATTERNS)


async def check_live_content(domain: str) -> dict[str, Any]:
    ip = await _resolve_ip(domain)
    if ip is None:
        return {"status": "ok", "has_live_site": False,
                "note": "domain does not resolve — nothing to fetch"}
    if not _is_safe_public_ip(ip):
        return {"status": "ok", "has_live_site": False,
                "note": "resolved to a private/internal address — refusing to fetch"}

    headers = {"User-Agent": "Mozilla/5.0 (compatible; DomainRiskScanner/1.0; "
                              "security scan, not indexing)"}
    resp = None
    protocol_used = None
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                  max_redirects=MAX_REDIRECTS, headers=headers) as client:
        # Fire HTTPS and HTTP concurrently: a hung/broken HTTPS listener would
        # otherwise burn a full TIMEOUT before HTTP is even attempted (worst
        # case ~2x). We still prefer HTTPS whenever it succeeds, and cancel the
        # HTTP attempt in that case so a normal site isn't loaded twice.
        https_task = asyncio.create_task(client.get(f"https://{domain}/"))
        http_task = asyncio.create_task(client.get(f"http://{domain}/"))
        try:
            resp = await https_task
            protocol_used = "https"
            await _cancel(http_task)
        except httpx.HTTPError:
            try:
                resp = await http_task
                protocol_used = "http"
            except httpx.HTTPError:
                resp = None

    if resp is None:
        return {"status": "ok", "has_live_site": False,
                "note": "resolves, but no web server answered on 443 or 80"}

    html = resp.text[:MAX_CHARS]
    title = _extract_title(html)
    risky = _scan_text(html)
    parked = _looks_parked(html, title)

    return {
        "status": "ok",
        "has_live_site": True,
        "protocol": protocol_used,
        "final_url": str(resp.url),
        "status_code": resp.status_code,
        "title": title,
        "is_parked": parked,
        "risky_hits": risky,
    }
