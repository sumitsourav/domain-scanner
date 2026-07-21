"""Domain risk scanner + P2P domain reselling marketplace — FastAPI entry point.

    uvicorn app.main:app --reload
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")  # must run before any module reads os.environ

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import init_db
from .domains import normalize_domain
from .marketplace import router as marketplace_router
from .scanning import run_full_scan

STATIC_DIR = ROOT_DIR / "static"

app = FastAPI(title="Domain Risk Scanner",
              description="Available ≠ safe: pre-purchase risk analysis for domain names, "
                          "plus a P2P marketplace to resell them with a risk report attached.")

app.include_router(marketplace_router)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/api/scan")
async def scan(domain: str = Query(..., min_length=3, max_length=253)):
    d = normalize_domain(domain)
    return await run_full_scan(d)


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/marketplace", include_in_schema=False)
async def marketplace_page():
    return FileResponse(STATIC_DIR / "marketplace.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
