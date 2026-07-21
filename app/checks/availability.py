"""Registration status via RDAP (the modern, structured replacement for WHOIS).

rdap.org is a bootstrap redirector: it 302s to the authoritative registry
RDAP server for the domain's TLD. A 404 means the registry has no record,
i.e. the domain is available to register.
"""

from __future__ import annotations

import datetime
from typing import Any

import httpx

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
TIMEOUT = 12.0


def _parse_events(events: list[dict]) -> dict[str, str | None]:
    out: dict[str, str | None] = {"registered": None, "expires": None, "updated": None}
    mapping = {
        "registration": "registered",
        "expiration": "expires",
        "last changed": "updated",
    }
    for ev in events or []:
        key = mapping.get(ev.get("eventAction", ""))
        if key and ev.get("eventDate"):
            out[key] = ev["eventDate"]
    return out


def _registrar_name(entities: list[dict]) -> str | None:
    for ent in entities or []:
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn" and len(item) >= 4:
                    return item[3]
            return ent.get("handle")
    return None


def _age_years(registered_iso: str | None) -> float | None:
    if not registered_iso:
        return None
    try:
        dt = datetime.datetime.fromisoformat(registered_iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return round((now - dt).days / 365.25, 1)


async def check_availability(domain: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT, follow_redirects=True,
            headers={"Accept": "application/rdap+json"},
        ) as client:
            resp = await client.get(RDAP_BOOTSTRAP.format(domain=domain))
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"RDAP lookup failed: {exc.__class__.__name__}"}

    if resp.status_code == 404:
        return {"status": "ok", "available": True}

    if resp.status_code != 200:
        return {"status": "error", "error": f"RDAP returned HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"status": "error", "error": "RDAP returned invalid JSON"}

    events = _parse_events(data.get("events", []))
    return {
        "status": "ok",
        "available": False,
        "registrar": _registrar_name(data.get("entities", [])),
        "registered": events["registered"],
        "expires": events["expires"],
        "updated": events["updated"],
        "age_years": _age_years(events["registered"]),
        "epp_status": data.get("status", []),
    }
