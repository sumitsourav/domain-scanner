"""Prior-use history via the Wayback Machine CDX API.

Two queries, run concurrently (archive.org is often slow or briefly 5xx):
  1. Yearly-collapsed snapshots of the root URL -> timeline (first/last seen,
     active years).
  2. Distinct archived URLs across the whole domain -> keyword scan against
     a risk lexicon (spam/scam verticals that poison a domain's reputation).

If only one query succeeds we still return partial history (years can be
approximated from the URL sample's capture timestamps) instead of failing
the whole check.
"""

from __future__ import annotations

import asyncio
import datetime
from typing import Any
from urllib.parse import unquote

import httpx

from ..risk_lexicon import PATTERNS

# Tightened from 20s: a timeout now falls back to the stale cache (see
# app/scan_cache.py) rather than a coverage gap, so failing faster is cheaper.
CDX = "https://web.archive.org/cdx/search/cdx"
TIMEOUT = 15.0
MAX_URLS = 800


async def _cdx(client: httpx.AsyncClient, params: dict) -> list[list[str]] | None:
    try:
        resp = await client.get(CDX, params=params)
        resp.raise_for_status()
        rows = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return rows[1:] if rows else []  # first row is the header


def _scan_urls(urls: list[str]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for url in urls:
        decoded = unquote(url)
        for cat, pattern in PATTERNS.items():
            if pattern.search(decoded):
                hits.setdefault(cat, [])
                if len(hits[cat]) < 5:  # keep evidence lists short
                    hits[cat].append(url)
    return hits


def _years_from_rows(rows: list[list[str]]) -> set[int]:
    return {int(r[0][:4]) for r in rows if r and len(r[0]) >= 4 and r[0][:4].isdigit()}


async def check_history(domain: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        timeline, url_rows = await asyncio.gather(
            _cdx(client, {
                "url": domain,
                "output": "json",
                "fl": "timestamp",
                "collapse": "timestamp:4",  # one row per calendar year
                "limit": "200",
            }),
            _cdx(client, {
                "url": domain,
                "matchType": "domain",
                "output": "json",
                "fl": "timestamp,original",
                "collapse": "urlkey",
                "limit": str(MAX_URLS),
            }),
        )

    if timeline is None and url_rows is None:
        return {"status": "error", "error": "Wayback Machine unreachable or timed out"}

    approximate = timeline is None
    years = set()
    if timeline:
        years |= _years_from_rows(timeline)
    if url_rows:
        years |= _years_from_rows(url_rows)

    if not years:
        return {"status": "ok", "has_history": False, "snapshot_years": [],
                "risky_hits": {}, "urls_scanned": 0}

    urls = [row[1] for row in (url_rows or []) if len(row) > 1]
    risky = _scan_urls(urls)

    years_sorted = sorted(years)
    current_year = datetime.datetime.now(datetime.timezone.utc).year
    first_year, last_year = years_sorted[0], years_sorted[-1]
    years_of_use = len(years_sorted)
    dormant_years = current_year - last_year

    return {
        "status": "ok",
        "has_history": True,
        "approximate": approximate,  # timeline query failed; years from URL sample
        "first_year": first_year,
        "last_year": last_year,
        "active_years": years_of_use,
        "snapshot_years": years_sorted,
        "dormant_years": dormant_years,
        # heavy past use that then went dark: classic drop-catch churn profile
        "dropped_after_use": years_of_use >= 3 and dormant_years >= 2,
        "urls_scanned": len(urls),
        "risky_hits": risky,
        "wayback_url": f"https://web.archive.org/web/*/{domain}",
    }
