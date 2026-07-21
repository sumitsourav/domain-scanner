"""Domain risk scanner — FastAPI entry point.

    uvicorn app.main:app --reload
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .checks.abuse import check_abuse
from .checks.availability import check_availability
from .checks.blacklists import check_blacklists
from .checks.certs import check_certs
from .checks.history import check_history
from .checks.mail import check_mail
from .checks.trademark import check_trademark
from .scoring import compute_score

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(title="Domain Risk Scanner",
              description="Available ≠ safe: pre-purchase risk analysis for domain names.")

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(rf"^(?:{LABEL}\.)+[a-z]{{2,63}}$")


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)   # strip scheme
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.removeprefix("www.").rstrip(".")
    if d.count(":") == 1:
        d = d.split(":")[0]                        # strip port
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(422, detail=f"Not a valid domain name: {raw!r}")
    if re.fullmatch(r"[\d.]+", d) or not DOMAIN_RE.fullmatch(d):
        raise HTTPException(422, detail=f"Not a valid domain name: {raw!r}")
    return d


@app.get("/api/scan")
async def scan(domain: str = Query(..., min_length=3, max_length=253)):
    d = normalize_domain(domain)
    started = time.monotonic()

    availability, blacklists, history, certs, mail, abuse = await asyncio.gather(
        check_availability(d),
        check_blacklists(d),
        check_history(d),
        check_certs(d),
        check_mail(d),
        check_abuse(d),
    )
    trademark = check_trademark(d)

    result = compute_score(d, availability, blacklists, history, trademark, mail, abuse)
    return {
        "domain": d,
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


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
