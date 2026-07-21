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
from .checks.mail import check_mail
from .checks.trademark import check_trademark
from .scoring import compute_score


async def run_full_scan(domain: str) -> dict[str, Any]:
    started = time.monotonic()

    availability, blacklists, history, certs, mail, abuse = await asyncio.gather(
        check_availability(domain),
        check_blacklists(domain),
        check_history(domain),
        check_certs(domain),
        check_mail(domain),
        check_abuse(domain),
    )
    trademark = check_trademark(domain)

    result = compute_score(domain, availability, blacklists, history, trademark, mail, abuse)
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
        },
        **result,
    }
