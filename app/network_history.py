"""Cross-referencing the accumulated scan history for a network-effect
signal: "this domain shares infrastructure with N previously-scanned
HIGH/SEVERE-risk domains." Gets more useful the more the tool is used,
starting from nothing on a fresh database.

Matching is deliberately narrow — exact resolved IP or exact nameserver
set, never ASN. ASN is far too coarse: Google and Cloudflare alone put
millions of unrelated domains behind AS15169 and AS13335 respectively (see
app/checks/infrastructure.py), so "shares an ASN with a bad domain" would
fire on a huge fraction of the internet. A shared IP or an identical
custom nameserver set is a much smaller, more meaningful coincidence.
"""

from __future__ import annotations

import datetime
from typing import Any

from .db import get_conn

HIGH_RISK_VERDICTS = ("HIGH", "SEVERE")


def log_scan(domain: str, infra: dict, score: int, verdict: str) -> None:
    if infra.get("status") != "ok":
        return
    nameservers = ",".join(infra.get("nameservers") or [])
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scans (domain, resolved_ip, nameservers, asn, asn_name,
                                   risk_score, risk_verdict, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(domain) DO UPDATE SET
                 resolved_ip=excluded.resolved_ip, nameservers=excluded.nameservers,
                 asn=excluded.asn, asn_name=excluded.asn_name,
                 risk_score=excluded.risk_score, risk_verdict=excluded.risk_verdict,
                 scanned_at=excluded.scanned_at""",
            (domain, infra.get("ip"), nameservers, infra.get("asn"), infra.get("asn_name"),
             score, verdict, datetime.datetime.now(datetime.timezone.utc).isoformat()),
        )


def find_shared_risk(domain: str, infra: dict) -> list[dict[str, Any]]:
    if infra.get("status") != "ok":
        return []
    ip = infra.get("ip")
    nameservers = ",".join(infra.get("nameservers") or [])

    match_clauses = []
    match_params: list = []
    if ip:
        match_clauses.append("resolved_ip = ?")
        match_params.append(ip)
    if nameservers:
        match_clauses.append("nameservers = ?")
        match_params.append(nameservers)
    if not match_clauses:
        return []

    verdict_placeholders = ",".join("?" * len(HIGH_RISK_VERDICTS))
    sql = (f"SELECT domain, resolved_ip, nameservers, risk_score, risk_verdict FROM scans "
           f"WHERE domain != ? AND risk_verdict IN ({verdict_placeholders}) "
           f"AND ({' OR '.join(match_clauses)}) ORDER BY risk_score DESC LIMIT 10")
    params = [domain, *HIGH_RISK_VERDICTS, *match_params]

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    matches = []
    for row in rows:
        shared_via = []
        if ip and row["resolved_ip"] == ip:
            shared_via.append("IP")
        if nameservers and row["nameservers"] == nameservers:
            shared_via.append("nameservers")
        matches.append({
            "domain": row["domain"],
            "risk_score": row["risk_score"],
            "risk_verdict": row["risk_verdict"],
            "shared_via": shared_via,
        })
    return matches
