"""Live email infrastructure: MX, SPF, and DMARC records.

This replaces guesswork with measurement. Where the blacklist check asks
"is this name already blocklisted," this asks "is the mail setup itself
sound" — a domain can be blacklist-clean today and still be one `+all`
away from becoming a spoofing playground.

For a domain that has never been used (no prior owner), none of these
records exist yet — that's expected and reported as "not configured,"
not as a risk. The one factor this feeds into scoring is a concretely
dangerous, well-documented misconfiguration: an SPF record ending in
`+all`, which tells every receiving server to accept mail from *any*
IP claiming to be this domain.

Uses public resolvers explicitly rather than the system default: some
ISP/router DNS proxies silently truncate or REFUSE multi-record TXT
answers (observed in the wild — a TXT query missing exactly the SPF
record among a dozen others), which would otherwise be mistaken for
"no SPF record configured." This is safe here — unlike the DNSBL zone
lookups in blacklists.py, plain MX/TXT resolution isn't subject to
Spamhaus-style anti-abuse blocking of public resolvers.
"""

from __future__ import annotations

from typing import Any

import dns.asyncresolver
import dns.resolver

DNS_LIFETIME = 6.0
PUBLIC_RESOLVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]


class ResolutionError(Exception):
    pass


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = PUBLIC_RESOLVERS
    r.lifetime = DNS_LIFETIME
    return r


async def _txt_records(name: str) -> list[str]:
    try:
        answer = await _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception as exc:
        raise ResolutionError(f"TXT lookup for {name} failed: {exc.__class__.__name__}") from exc
    out = []
    for rr in answer:
        # dnspython yields a tuple of byte-strings per TXT record; join+decode.
        out.append(b"".join(rr.strings).decode("utf-8", "replace"))
    return out


def _spf_qualifier(spf: str) -> str | None:
    for mech in spf.split():
        if mech.endswith("all"):
            return mech[0] if mech[0] in "+-~?" else "+"
    return None


def _dmarc_policy(dmarc: str) -> str | None:
    for tag in dmarc.split(";"):
        tag = tag.strip()
        if tag.lower().startswith("p="):
            return tag.split("=", 1)[1].strip().lower()
    return None


async def check_mail(domain: str) -> dict[str, Any]:
    try:
        mx_answer = await _resolver().resolve(domain, "MX")
        mx_hosts = sorted(
            [f"{rr.preference} {str(rr.exchange).rstrip('.')}" for rr in mx_answer]
        )
        has_mx = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        mx_hosts, has_mx = [], False
    except Exception as exc:
        return {"status": "error", "error": f"MX lookup failed: {exc.__class__.__name__}"}

    try:
        txts = await _txt_records(domain)
        dmarc_txts = await _txt_records(f"_dmarc.{domain}")
    except ResolutionError as exc:
        return {"status": "error", "error": str(exc)}

    spf_record = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    spf_qualifier = _spf_qualifier(spf_record) if spf_record else None
    spf_permissive = spf_qualifier == "+"

    dmarc_record = next((t for t in dmarc_txts if t.lower().startswith("v=dmarc1")), None)
    dmarc_policy = _dmarc_policy(dmarc_record) if dmarc_record else None

    return {
        "status": "ok",
        "has_mx": has_mx,
        "mx_hosts": mx_hosts,
        "spf": {
            "present": spf_record is not None,
            "record": spf_record,
            "qualifier": spf_qualifier,
            "permissive": spf_permissive,
        },
        "dmarc": {
            "present": dmarc_record is not None,
            "record": dmarc_record,
            "policy": dmarc_policy,
        },
        "configured": has_mx or spf_record is not None or dmarc_record is not None,
    }
