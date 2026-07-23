"""Shared scan pipeline — used by the standalone /api/scan endpoint and by
marketplace listing creation (every listing must carry a scan; see
app/marketplace.py). One implementation so the risk report shown on a
listing is exactly what a buyer would get running the scanner themselves.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .checks.abuse import check_abuse
from .checks.availability import check_availability
from .checks.blacklists import check_blacklists
from .checks.certs import check_certs
from .checks.history import check_history
from .checks.infrastructure import check_infrastructure
from .checks.live_content import check_live_content
from .checks.mail import check_mail
from .checks.reputation import registrar_trust, tld_risk
from .checks.trademark import check_trademark
from .network_history import find_shared_risk, log_scan
from .scan_cache import cached_check
from .scoring import compute_score

# crt.sh and Wayback are the two slow, flaky external checks, and both return
# slowly-changing historical data — so they're cached (fresh for a day) with a
# stale-on-error fallback. See app/scan_cache.py.
CERTS_TTL_SECONDS = 24 * 3600
HISTORY_TTL_SECONDS = 24 * 3600


async def run_full_scan(domain: str) -> dict[str, Any]:
    started = time.monotonic()

    availability, blacklists, history, certs, mail, abuse, infra, live = await asyncio.gather(
        check_availability(domain),
        check_blacklists(domain),
        cached_check("history", domain, check_history, HISTORY_TTL_SECONDS),
        cached_check("certs", domain, check_certs, CERTS_TTL_SECONDS),
        check_mail(domain),
        check_abuse(domain),
        check_infrastructure(domain),
        check_live_content(domain),
    )
    trademark = check_trademark(domain)
    # Pure/offline, no I/O — registrar comes from the availability lookup above.
    reputation = {
        "status": "ok",
        "tld": tld_risk(domain),
        "registrar": registrar_trust(availability.get("registrar")),
    }
    # Cross-reference against domains scanned before this one — needs infra's
    # fingerprint, so it can't join the gather above.
    shared_infra = find_shared_risk(domain, infra)

    result = compute_score(domain, availability, blacklists, history, trademark, mail,
                           abuse, reputation, live, shared_infra)

    # Log *after* scoring and shared-risk lookup, so this scan can't match
    # against itself and future scans see this domain's real, final verdict.
    log_scan(domain, infra, result["score"], result["verdict"])

    return {
        "domain": domain,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "checks": {
            "availability": availability,
            "blacklists": blacklists,
            "history": history,
            "trademark": trademark,
            "certs": certs,
            "mail": mail,
            "abuse": abuse,
            "reputation": reputation,
            "infrastructure": infra,
            "live_content": live,
        },
        "shared_infrastructure": shared_infra,
        **result,
    }
