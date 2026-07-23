"""Prior-operator fingerprint via Certificate Transparency logs (crt.sh).

Every publicly-trusted TLS certificate is logged permanently in CT logs,
independent of whether the site still exists or Wayback ever crawled it.
Subdomains seen historically (mail., admin., shop., api., a scam brand
name embedded in a sub-label, ...) reveal what infrastructure a domain
carried under previous owners — a signal Wayback and WHOIS both miss.

Informational, not scored: subdomain footprints correlate with "this
domain was actually used for something," not with risk in either
direction, so this check feeds the evidence cards but not the score.

crt.sh is a free community service known to be slow/overloaded; treat
non-200s and timeouts as a plain coverage gap, never as "no certs."
"""

from __future__ import annotations

import datetime
import asyncio
from typing import Any

import httpx

CRTSH = "https://crt.sh/"
TIMEOUT = 10.0
RETRY_BACKOFF = 0.6
MAX_ROWS = 500
MAX_SUBDOMAINS_SHOWN = 25

_NO_CERTS = {"status": "ok", "has_certs": False, "subdomains": [], "cert_count": 0}


def _dedupe_names(rows: list[dict]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        for raw in (row.get("name_value") or "").split("\n"):
            name = raw.strip().lower().removeprefix("*.")
            if name:
                names.add(name)
    return names


async def _fetch_rows(domain: str) -> tuple[list[dict] | None, str | None]:
    """Returns (rows, error). rows == [] means 'no certs' (not an error).

    crt.sh 5xx responses are frequently transient (observed flipping
    502 -> 200 within seconds), so a 5xx or connection error gets one quick
    retry. A timeout does NOT retry — retrying a hung request just doubles
    the wait for no likely gain.
    """
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for attempt in range(2):  # one try + one retry
            try:
                resp = await client.get(CRTSH, params={"q": domain, "output": "json"})
            except httpx.TimeoutException:
                return None, "crt.sh timed out"
            except httpx.HTTPError as exc:
                if attempt == 0:
                    await asyncio.sleep(RETRY_BACKOFF)
                    continue
                return None, f"crt.sh unreachable: {exc.__class__.__name__}"

            if resp.status_code == 404:
                return [], None
            if resp.status_code >= 500 and attempt == 0:
                await asyncio.sleep(RETRY_BACKOFF)
                continue
            if resp.status_code != 200:
                return None, f"crt.sh returned HTTP {resp.status_code}"
            try:
                return resp.json(), None
            except ValueError:
                return None, "crt.sh returned invalid JSON"
    return None, "crt.sh unavailable after retry"


async def check_certs(domain: str) -> dict[str, Any]:
    rows, error = await _fetch_rows(domain)
    if error is not None:
        return {"status": "error", "error": error}
    if not rows:
        return dict(_NO_CERTS)

    rows = rows[:MAX_ROWS]
    names = _dedupe_names(rows)
    subdomains = sorted(n for n in names if n != domain and n.endswith(f".{domain}"))

    dates = [r["not_before"] for r in rows if r.get("not_before")]
    first_seen = min(dates) if dates else None
    last_seen = max(dates) if dates else None
    recent_activity = False
    if last_seen:
        try:
            dt = datetime.datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                # crt.sh timestamps are sometimes bare (no "Z"/offset); they're UTC.
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            recent_activity = (datetime.datetime.now(datetime.timezone.utc) - dt).days < 365
        except (ValueError, TypeError):
            pass

    return {
        "status": "ok",
        "has_certs": True,
        "cert_count": len(rows),
        "cert_count_is_floor": len(rows) == MAX_ROWS,
        "subdomain_count": len(subdomains),
        "subdomains": subdomains[:MAX_SUBDOMAINS_SHOWN],
        "first_cert": first_seen[:10] if first_seen else None,
        "last_cert": last_seen[:10] if last_seen else None,
        "recent_activity": recent_activity,
        "crtsh_url": f"https://crt.sh/?q={domain}",
    }
