"""Aggregate per-check signals into a single 0-100 risk score.

Additive model with a cap: each factor contributes points and a
human-readable evidence line, so the UI can show exactly why a domain
scored what it did. Checks that errored contribute nothing but are
surfaced as coverage gaps.
"""

from __future__ import annotations

from typing import Any

BANDS = [
    (70, "SEVERE", "Do not register — serious reputation damage attached to this name."),
    (45, "HIGH", "High risk — expect deliverability and trust problems out of the box."),
    (20, "MODERATE", "Some baggage — investigate the flagged items before buying."),
    (0, "LOW", "No significant risk signals found. Reasonable to register."),
]

LIST_WEIGHTS = {
    "Spamhaus DBL": 45,
    "SURBL": 30,
    "URIBL": 30,
    "Spamhaus ZEN": 15,
    "Barracuda": 15,
}


def compute_score(domain: str, availability: dict, blacklists: dict,
                  history: dict, trademark: dict, mail: dict,
                  abuse: dict) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []
    unknown_sources: list[str] = []

    def add(points: int, label: str, detail: str) -> None:
        factors.append({"points": points, "label": label, "detail": detail})

    # --- blacklists -------------------------------------------------------
    mail_risk = False
    if blacklists.get("status") == "ok":
        unknown_sources += blacklists.get("unknown", [])
        for entry in blacklists.get("domain_lists", []) + blacklists.get("ip_lists", []):
            if entry.get("listed"):
                weight = LIST_WEIGHTS.get(entry["list"], 15)
                reasons = ", ".join(entry.get("reasons") or []) or "listed"
                add(weight, f"Listed on {entry['list']}", reasons)
                if entry["list"] in ("Spamhaus DBL", "SURBL", "URIBL"):
                    mail_risk = True
    else:
        unknown_sources.append("blacklists")

    # --- history ----------------------------------------------------------
    if history.get("status") == "ok":
        risky = history.get("risky_hits") or {}
        if risky:
            n_cats = len(risky)
            pts = min(25 + (n_cats - 1) * 5, 40)
            cats = ", ".join(sorted(risky))
            add(pts, "Risky content in archived history", f"categories: {cats}")
        if history.get("dropped_after_use"):
            add(10, "Dropped after years of active use",
                f"active {history['first_year']}–{history['last_year']}, "
                f"dark for {history['dormant_years']}+ years (drop-catch churn profile)")
    else:
        unknown_sources.append("Wayback history")

    # --- trademark --------------------------------------------------------
    if trademark.get("status") == "ok":
        if trademark.get("exact_match"):
            add(30, "Exact famous-brand label", trademark["exact_match"])
        elif trademark.get("contains_brands"):
            add(30, "Contains famous brand name",
                ", ".join(trademark["contains_brands"]))
        elif trademark.get("typosquat_of"):
            add(25, "One edit away from famous brand (typosquat)",
                ", ".join(trademark["typosquat_of"]))

    # --- mail infrastructure -----------------------------------------------
    spf_permissive = False
    if mail.get("status") == "ok":
        spf = mail.get("spf") or {}
        if spf.get("permissive"):
            spf_permissive = True
            add(15, "SPF record permits any sender (+all)",
                "historically abused to spoof mail from this domain — "
                "legitimate mail setups use ~all or -all")
    else:
        unknown_sources.append("mail infrastructure")

    # --- malware hosting (URLhaus, optional) --------------------------------
    if abuse.get("status") == "ok" and abuse.get("listed"):
        threats = ", ".join(abuse.get("threats") or []) or "malware distribution"
        add(35, "Hosted malware (URLhaus)",
            f"{abuse.get('url_count')} malicious URL(s) recorded — {threats}")
    elif abuse.get("status") == "error":
        unknown_sources.append("URLhaus")
    # status == "disabled" (no API key configured) is not a coverage gap —
    # it's an opt-in check the operator hasn't turned on.

    score = min(sum(f["points"] for f in factors), 100)
    for threshold, verdict, advice in BANDS:
        if score >= threshold:
            break

    # Email deliverability sub-verdict: domain blacklists are what mail
    # servers actually consult, so they dominate this axis; a permissive
    # SPF record is the next strongest signal since it is directly
    # exploitable for spoofing regardless of blacklist status.
    if mail_risk:
        deliverability = {"verdict": "POOR",
                          "detail": "Domain is on blocklists that mail providers consult; "
                                    "email from it will be rejected or spam-foldered."}
    elif spf_permissive:
        deliverability = {"verdict": "POOR",
                          "detail": "SPF record ends in +all, permitting any server to send "
                                    "as this domain — a spoofing risk independent of blacklist status."}
    elif "blacklists" in unknown_sources:
        deliverability = {"verdict": "UNKNOWN",
                          "detail": "Blacklist checks did not complete."}
    elif history.get("status") == "ok" and history.get("risky_hits"):
        deliverability = {"verdict": "WATCH",
                          "detail": "Not currently blocklisted, but prior spammy use can "
                                    "linger in private filter reputation (Gmail, Microsoft)."}
    else:
        deliverability = {"verdict": "GOOD",
                          "detail": "No blocklist or reputation signals against this name."}

    return {
        "score": score,
        "verdict": verdict,
        "advice": advice,
        "factors": sorted(factors, key=lambda f: -f["points"]),
        "deliverability": deliverability,
        "coverage_gaps": sorted(set(unknown_sources)),
    }
