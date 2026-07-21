"""DNS blacklist (DNSBL) lookups.

Two kinds of lists:
  * Domain lists (Spamhaus DBL, SURBL, URIBL) — keyed by the domain name
    itself, so they work even for currently-unregistered domains. These are
    the core "toxic name" signal and directly drive mail-server rejection.
  * IP lists (Spamhaus ZEN, Barracuda) — keyed by the IP the domain resolves
    to today; only meaningful when the domain has an A record.

Semantics: NXDOMAIN = not listed. Some lists return sentinel codes when the
query comes from a blocked public resolver (Spamhaus 127.255.255.x,
URIBL 127.0.0.1) — those are reported as "unknown", never as listings.
"""

from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver
import dns.resolver

DNS_LIFETIME = 5.0

SPAMHAUS_DBL_CODES = {
    2: "spam domain",
    4: "phishing domain",
    5: "malware domain",
    6: "botnet C&C domain",
    102: "abused legit spam",
    103: "abused spammed redirector",
    104: "abused legit phishing",
    105: "abused legit malware",
    106: "abused legit botnet C&C",
}

SURBL_BITS = {
    8: "phishing",
    16: "malware",
    64: "abuse",
    128: "cracked site",
}

SPAMHAUS_ZEN_CODES = {
    2: "SBL (spam source)",
    3: "SBL CSS (snowshoe spam)",
    4: "XBL (exploited/botnet)",
    9: "SBL DROP (hijacked netblock)",
    10: "PBL (dynamic/residential IP)",
    11: "PBL (dynamic/residential IP)",
}


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.lifetime = DNS_LIFETIME
    return r


async def _query(name: str) -> list[str] | None | str:
    """Returns list of A-record strings, None if NXDOMAIN, or 'error'."""
    try:
        answer = await _resolver().resolve(name, "A")
        return [rr.address for rr in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception:
        return "error"


def _last_octet(addr: str) -> int:
    return int(addr.rsplit(".", 1)[-1])


async def _check_spamhaus_dbl(domain: str) -> dict[str, Any]:
    res = await _query(f"{domain}.dbl.spamhaus.org")
    if res == "error":
        return {"list": "Spamhaus DBL", "status": "unknown", "listed": False}
    if res is None:
        return {"list": "Spamhaus DBL", "status": "ok", "listed": False}
    codes = [_last_octet(a) for a in res if a.startswith("127.0.1.")]
    if any(a.startswith("127.255.255.") for a in res) or not codes:
        return {"list": "Spamhaus DBL", "status": "unknown", "listed": False,
                "note": "query refused (public resolver blocked)"}
    reasons = [SPAMHAUS_DBL_CODES.get(c, f"code {c}") for c in codes]
    return {"list": "Spamhaus DBL", "status": "ok", "listed": True, "reasons": reasons}


async def _check_surbl(domain: str) -> dict[str, Any]:
    res = await _query(f"{domain}.multi.surbl.org")
    if res == "error":
        return {"list": "SURBL", "status": "unknown", "listed": False}
    if res is None:
        return {"list": "SURBL", "status": "ok", "listed": False}
    reasons = []
    for addr in res:
        if addr.startswith("127.0.0."):
            mask = _last_octet(addr)
            reasons += [label for bit, label in SURBL_BITS.items() if mask & bit]
    if not reasons:
        return {"list": "SURBL", "status": "unknown", "listed": False,
                "note": "unrecognized response"}
    return {"list": "SURBL", "status": "ok", "listed": True, "reasons": sorted(set(reasons))}


async def _check_uribl(domain: str) -> dict[str, Any]:
    res = await _query(f"{domain}.multi.uribl.com")
    if res == "error":
        return {"list": "URIBL", "status": "unknown", "listed": False}
    if res is None:
        return {"list": "URIBL", "status": "ok", "listed": False}
    reasons = []
    for addr in res:
        if addr == "127.0.0.1":
            return {"list": "URIBL", "status": "unknown", "listed": False,
                    "note": "query refused (public resolver blocked)"}
        if addr.startswith("127.0.0."):
            mask = _last_octet(addr)
            if mask & 2:
                reasons.append("black (spam)")
            if mask & 4:
                reasons.append("grey")
            if mask & 8:
                reasons.append("red (heavy abuse)")
    if not reasons:
        return {"list": "URIBL", "status": "unknown", "listed": False}
    return {"list": "URIBL", "status": "ok", "listed": True, "reasons": reasons}


async def _check_ip_list(ip: str, zone: str, name: str,
                         codes: dict[int, str] | None = None) -> dict[str, Any]:
    reversed_ip = ".".join(reversed(ip.split(".")))
    res = await _query(f"{reversed_ip}.{zone}")
    if res == "error":
        return {"list": name, "status": "unknown", "listed": False, "ip": ip}
    if res is None:
        return {"list": name, "status": "ok", "listed": False, "ip": ip}
    if any(a.startswith("127.255.255.") for a in res):
        return {"list": name, "status": "unknown", "listed": False, "ip": ip,
                "note": "query refused (public resolver blocked)"}
    reasons = None
    if codes:
        reasons = [codes.get(_last_octet(a), f"code {_last_octet(a)}")
                   for a in res if a.startswith("127.0.0.")]
    return {"list": name, "status": "ok", "listed": True, "ip": ip, "reasons": reasons}


async def check_blacklists(domain: str) -> dict[str, Any]:
    tasks = [
        _check_spamhaus_dbl(domain),
        _check_surbl(domain),
        _check_uribl(domain),
    ]

    # IP lists only apply if the domain resolves right now.
    ips = await _query(domain)
    resolves = isinstance(ips, list) and bool(ips)
    if resolves:
        ip = ips[0]
        tasks.append(_check_ip_list(ip, "zen.spamhaus.org", "Spamhaus ZEN",
                                    SPAMHAUS_ZEN_CODES))
        tasks.append(_check_ip_list(ip, "b.barracudacentral.org", "Barracuda"))

    results = await asyncio.gather(*tasks)
    domain_lists = results[:3]
    ip_lists = list(results[3:])

    return {
        "status": "ok",
        "resolves": resolves,
        "resolved_ip": ips[0] if resolves else None,
        "domain_lists": domain_lists,
        "ip_lists": ip_lists,
        "listed_on": [r["list"] for r in results if r.get("listed")],
        "unknown": [r["list"] for r in results if r["status"] == "unknown"],
    }
