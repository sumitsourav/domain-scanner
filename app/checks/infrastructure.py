"""Infrastructure fingerprint: resolved IP, nameservers, and ASN.

This check only fingerprints the *current* domain — it doesn't know about
any other domain. The cross-referencing that turns this into a "shares
infrastructure with N previously-scanned high-risk domains" signal lives in
app/network_history.py, which needs this fingerprint plus our own
accumulated scan history to do anything useful.

ASN lookup uses Team Cymru's free, keyless DNS-based IP-to-ASN service
(a long-standing, widely-used technique — no API key, no rate-limit key
needed): reverse the IP into "origin.asn.cymru.com" for the ASN + prefix,
then "asn.cymru.com" for the AS's registered name.
"""

from __future__ import annotations

from typing import Any

import dns.asyncresolver

DNS_LIFETIME = 6.0


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.lifetime = DNS_LIFETIME
    return r


async def _resolve(name: str, rdtype: str) -> list[str] | None:
    try:
        answer = await _resolver().resolve(name, rdtype)
        return [str(rr).rstrip(".") for rr in answer]
    except Exception:
        return None


def _txt_value(strings: list[str]) -> str | None:
    return strings[0].strip('"') if strings else None


async def _asn_lookup(ip: str) -> dict[str, Any]:
    reversed_ip = ".".join(reversed(ip.split(".")))
    origin = await _resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
    origin_val = _txt_value(origin or [])
    if not origin_val:
        return {"asn": None, "asn_name": None, "country": None}

    # "ASN | BGP Prefix | Country | Registry | Allocated"
    parts = [p.strip() for p in origin_val.split("|")]
    asn = parts[0] if parts else None
    country = parts[2] if len(parts) > 2 else None

    asn_name = None
    if asn:
        name_row = await _resolve(f"AS{asn}.asn.cymru.com", "TXT")
        name_val = _txt_value(name_row or [])
        if name_val:
            # "ASN | Country | Registry | Allocated | AS Name"
            name_parts = [p.strip() for p in name_val.split("|")]
            if len(name_parts) >= 5:
                asn_name = name_parts[4]

    return {"asn": asn, "asn_name": asn_name, "country": country}


async def check_infrastructure(domain: str) -> dict[str, Any]:
    a_records = await _resolve(domain, "A")
    ns_records = await _resolve(domain, "NS")
    ip = a_records[0] if a_records else None

    asn_info: dict[str, Any] = {"asn": None, "asn_name": None, "country": None}
    if ip:
        asn_info = await _asn_lookup(ip)

    nameservers = sorted(ns.lower() for ns in (ns_records or []))
    return {
        "status": "ok",
        "resolves": ip is not None,
        "ip": ip,
        "nameservers": nameservers,
        **asn_info,
    }
