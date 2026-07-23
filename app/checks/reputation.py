"""Offline reputation heuristics: TLD abuse-rate tier and registrar trust tier.

Both are static, hand-maintained tables — not live feeds, and not scored
symmetrically. TLD tiers reflect well-documented, consistently-repeated
findings from public abuse reports (Spamhaus "World's Most Abused TLDs",
Interisle Cybercrime Supply Chain reports): cheap/free-registration new
gTLDs are abused at rates orders of magnitude above legacy TLDs, year over
year. This is a prior, not a verdict, so it's weighted modestly relative to
live signals like a Spamhaus DBL listing.

Registrar trust is deliberately one-directional — a small allowlist of
registrars well-documented as corporate/brand-protection specialists
(the ones big brands specifically choose for their low-abuse, high-security
posture). There is no "risky registrar" list: naming specific companies as
abuse-prone in scoring code asserts a reputational claim this app has no
live way to verify, and any given registrar's abuse profile can shift
entirely under new ownership or policy. So this only ever adds a positive,
informational note — never a risk-score factor.
"""

from __future__ import annotations

from typing import Any

# Consistently flagged as high-abuse in Spamhaus/Interisle TLD reports —
# cheap or historically-free registration with little abuse enforcement.
HIGH_ABUSE_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "top", "xyz", "club", "work", "link", "click", "live", "icu", "cyou",
    "buzz", "rest", "fit", "quest", "cfd", "bond", "beauty", "surf", "sbs",
    "cam", "monster", "mom", "lol", "date", "loan", "download", "stream",
    "gdn", "men", "party", "science", "review", "trade", "webcam", "win",
}
# Elevated but not extreme — mixed reputations, some legitimate heavy use.
ELEVATED_ABUSE_TLDS = {
    "info", "biz", "cc", "ws", "pw", "su", "site", "online",
    "shop", "store", "vip", "life", "world", "space",
}
# Restricted registration (verified institutional applicants only).
RESTRICTED_TLDS = {"gov", "mil", "edu"}

TLD_WEIGHTS = {"high": 10, "elevated": 5}


def tld_risk(domain: str) -> dict[str, Any]:
    tld = domain.rsplit(".", 1)[-1]
    if tld in HIGH_ABUSE_TLDS:
        tier = "high"
        note = f".{tld} is flagged as high-abuse in industry spam/phishing TLD reports"
    elif tld in ELEVATED_ABUSE_TLDS:
        tier = "elevated"
        note = f".{tld} sees elevated abuse rates relative to legacy TLDs"
    elif tld in RESTRICTED_TLDS:
        tier = "restricted"
        note = f".{tld} has restricted, verified-applicant-only registration"
    else:
        tier = "neutral"
        note = None
    return {"tld": tld, "tier": tier, "note": note, "points": TLD_WEIGHTS.get(tier, 0)}


# Substring match against the registrar name RDAP returns (varies in
# formatting — "MarkMonitor Inc.", "CSC Corporate Domains, Inc.", etc.).
PREMIUM_REGISTRARS = [
    "markmonitor", "csc corporate domains", "cscglobal", "csc global",
    "safenames", "com laude", "nom-iq", "safebrands", "ascio",
]


def registrar_trust(registrar: str | None) -> dict[str, Any]:
    if not registrar:
        return {"tier": "unknown", "note": None}
    lowered = registrar.lower()
    if any(name in lowered for name in PREMIUM_REGISTRARS):
        return {"tier": "premium",
                "note": f"{registrar} specializes in corporate/brand-protection registrations — "
                        "a pattern typical of actively-defended, high-value domains"}
    return {"tier": "standard", "note": None}
