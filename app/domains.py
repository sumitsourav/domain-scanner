"""Domain name normalization/validation, shared by the scanner endpoint
and marketplace listing creation.
"""

from __future__ import annotations

import re

from fastapi import HTTPException

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
