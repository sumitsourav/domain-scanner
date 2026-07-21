"""Malware-hosting history via URLhaus (abuse.ch).

Optional: abuse.ch locked their APIs behind a free Auth-Key in their 2023
crackdown on abusive scraping, so this is no longer keyless like the rest
of the app's checks. It only runs if ABUSECH_AUTH_KEY is set in the
environment; otherwise it reports "not enabled" and is excluded from the
score and from coverage-gap warnings (absence of an optional check is not
a failure). Get a free key at https://auth.abuse.ch/.

Signal: distinct from spam/phishing DNSBLs — this flags domains that have
directly hosted malware payloads or C2 infrastructure, historically or
currently.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
TIMEOUT = 12.0


async def check_abuse(domain: str) -> dict[str, Any]:
    key = os.environ.get("ABUSECH_AUTH_KEY")
    if not key:
        return {"status": "disabled",
                "note": "URLhaus check requires a free ABUSECH_AUTH_KEY env var "
                        "(https://auth.abuse.ch/) — skipped."}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                URLHAUS_HOST_API,
                data={"host": domain},
                headers={"Auth-Key": key},
            )
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"URLhaus unreachable: {exc.__class__.__name__}"}

    if resp.status_code in (401, 403):
        return {"status": "error", "error": "URLhaus rejected the Auth-Key"}
    if resp.status_code != 200:
        return {"status": "error", "error": f"URLhaus returned HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"status": "error", "error": "URLhaus returned invalid JSON"}

    query_status = data.get("query_status")
    if query_status == "no_results":
        return {"status": "ok", "listed": False, "url_count": 0}
    if query_status != "ok":
        return {"status": "error", "error": f"URLhaus query_status={query_status}"}

    urls = data.get("urls") or []
    threats = sorted({u.get("threat") for u in urls if u.get("threat")})
    return {
        "status": "ok",
        "listed": len(urls) > 0,
        "url_count": len(urls),
        "threats": threats,
        "sample_urls": [u.get("url") for u in urls[:5] if u.get("url")],
    }
