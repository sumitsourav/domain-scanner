"""A freshness cache with stale-on-error fallback, for slow/flaky external
checks (crt.sh, Wayback — see app/checks/certs.py, history.py).

Both wins in one layer:
  * Latency — a repeat scan within the TTL skips the network entirely.
    Since the whole scan is gather-bounded by its slowest check, taking
    these two off the repeat path is the biggest available speedup.
  * Reliability — when the live call fails (5xx, timeout), we serve the
    last good result instead of a coverage gap. Safe here specifically
    because certs and archive history are slowly-changing historical data;
    a day-old cert list beats "crt.sh unreachable". Do NOT wrap volatile
    signals like blacklist status this way.

Only successful results (status == "ok") are cached. Each returned result
carries a `cache` marker so callers/UI can be honest about freshness:
  {"hit": bool, "stale": bool, "age_seconds": int}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from .db import get_conn

FetchFn = Callable[[str], Awaitable[dict[str, Any]]]


def _read(source: str, domain: str) -> tuple[dict, datetime] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT payload, fetched_at FROM check_cache WHERE source = ? AND domain = ?",
            (source, domain),
        ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row["payload"])
    except (ValueError, TypeError):
        return None
    return payload, datetime.fromisoformat(row["fetched_at"])


def _write(source: str, domain: str, payload: dict, when: datetime) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO check_cache (source, domain, payload, fetched_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(source, domain) DO UPDATE SET
                 payload = excluded.payload, fetched_at = excluded.fetched_at""",
            (source, domain, json.dumps(payload), when.isoformat()),
        )


def _mark(payload: dict, *, hit: bool, stale: bool, age: float) -> dict:
    return {**payload, "cache": {"hit": hit, "stale": stale, "age_seconds": int(age)}}


async def cached_check(source: str, domain: str, fetch: FetchFn,
                       fresh_ttl_seconds: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    cached = _read(source, domain)

    # Fresh enough → skip the network entirely.
    if cached is not None:
        payload, fetched_at = cached
        age = (now - fetched_at).total_seconds()
        if age < fresh_ttl_seconds:
            return _mark(payload, hit=True, stale=False, age=age)

    # Cache miss or stale → go live.
    try:
        result = await fetch(domain)
    except Exception:
        result = {"status": "error", "error": f"{source} check raised unexpectedly"}

    if result.get("status") == "ok":
        _write(source, domain, result, now)
        return _mark(result, hit=False, stale=False, age=0)

    # Live call failed — serve the last good result rather than a gap.
    if cached is not None:
        payload, fetched_at = cached
        age = (now - fetched_at).total_seconds()
        return _mark(payload, hit=True, stale=True, age=age)

    # Nothing cached and the live call failed — return the live error as-is.
    return result
