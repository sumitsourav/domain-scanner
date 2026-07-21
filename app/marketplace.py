"""P2P domain reselling marketplace.

Trust model (three layers, no in-app payments):
  1. Risk score gate — every listing carries a full scan from the same
     pipeline as the standalone scanner (app/scanning.py), cached at
     listing time and re-runnable. Full disclosure, not a score
     threshold: a MODERATE-risk domain can still be listed, but never
     unscanned.
  2. Seller reputation — star ratings, unlocked only after a trade is
     marked *completed* (not merely "offer accepted" — an agreement can
     still fall through before the off-platform transfer actually
     happens).
  3. Manual verification badge — operator-toggled via an admin-token
     endpoint, same env-var-gated pattern as the optional URLhaus check.

No money moves through this app. An accepted offer reveals both
parties' emails so they can finalize the domain transfer and payment
off-platform (registrar push, escrow.com, wire, whatever they agree).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field

from .auth import (
    SESSION_COOKIE,
    create_session,
    destroy_session,
    get_current_user,
    hash_password,
    require_user,
    verify_password,
)
from .db import get_conn
from .domains import normalize_domain
from .scanning import run_full_scan

router = APIRouter()

COOKIE_KWARGS = dict(httponly=True, samesite="lax", max_age=30 * 24 * 3600, path="/")


# --------------------------------------------------------------------------
# request bodies
# --------------------------------------------------------------------------

class SignupBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    display_name: str = Field(min_length=1, max_length=80)


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class ListingCreateBody(BaseModel):
    domain: str
    price_usd: Optional[float] = Field(default=None, ge=0)
    description: Optional[str] = Field(default=None, max_length=2000)


class OfferCreateBody(BaseModel):
    amount_usd: Optional[float] = Field(default=None, ge=0)
    message: Optional[str] = Field(default=None, max_length=2000)


class RateBody(BaseModel):
    stars: int = Field(ge=1, le=5)
    comment: Optional[str] = Field(default=None, max_length=1000)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def rating_summary(conn, user_id: int) -> dict:
    row = conn.execute(
        "SELECT AVG(stars) AS avg_stars, COUNT(*) AS n FROM ratings WHERE ratee_id = ?",
        (user_id,),
    ).fetchone()
    return {
        "avg_stars": round(row["avg_stars"], 1) if row["avg_stars"] is not None else None,
        "rating_count": row["n"],
    }


def public_user(conn, user_id: int) -> dict:
    row = conn.execute(
        "SELECT id, display_name, verified, created_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(404, detail="User not found")
    return {**dict(row), "verified": bool(row["verified"]), **rating_summary(conn, user_id)}


def serialize_listing(conn, row, viewer_id: Optional[int]) -> dict:
    d = dict(row)
    d["is_mine"] = viewer_id == d["seller_id"]
    d["seller"] = public_user(conn, d["seller_id"])
    del d["seller_id"]
    d["scan"] = json.loads(d["scan_json"]) if d["scan_json"] else None
    del d["scan_json"]
    return d


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

@router.post("/api/auth/signup")
def signup(body: SignupBody, response: Response):
    pw_hash, salt = hash_password(body.password)
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (body.email,)).fetchone()
        if existing:
            raise HTTPException(409, detail="An account with this email already exists")
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, password_salt, display_name, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (body.email, pw_hash, salt, body.display_name, now_iso()),
        )
        user_id = cur.lastrowid
    token, _ = create_session(user_id)
    response.set_cookie(SESSION_COOKIE, token, **COOKIE_KWARGS)
    return {"id": user_id, "email": body.email, "display_name": body.display_name}


@router.post("/api/auth/login")
def login(body: LoginBody, response: Response):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, password_hash, password_salt, display_name FROM users WHERE email = ?",
            (body.email,),
        ).fetchone()
    if row is None or not verify_password(body.password, row["password_salt"], row["password_hash"]):
        raise HTTPException(401, detail="Incorrect email or password")
    token, _ = create_session(row["id"])
    response.set_cookie(SESSION_COOKIE, token, **COOKIE_KWARGS)
    return {"id": row["id"], "email": body.email, "display_name": row["display_name"]}


@router.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        destroy_session(token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/auth/me")
def me(request: Request):
    user = get_current_user(request)
    if user is None:
        return {"user": None}
    with get_conn() as conn:
        return {"user": public_user(conn, user["id"]) | {"email": user["email"]}}


# --------------------------------------------------------------------------
# listings
# --------------------------------------------------------------------------

@router.post("/api/listings")
async def create_listing(body: ListingCreateBody, user: dict = Depends(require_user)):
    domain = normalize_domain(body.domain)
    scan = await run_full_scan(domain)
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO listings
               (seller_id, domain, price_usd, description, status,
                risk_score, risk_verdict, scan_json, scanned_at, created_at)
               VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)""",
            (user["id"], domain, body.price_usd, body.description,
             scan["score"], scan["verdict"], json.dumps(scan), now_iso(), now_iso()),
        )
        listing_id = cur.lastrowid
        row = conn.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
        return serialize_listing(conn, row, user["id"])


@router.get("/api/listings")
def browse_listings(
    request: Request,
    verdict: Optional[str] = None,
    max_price: Optional[float] = None,
    q: Optional[str] = None,
):
    viewer = get_current_user(request)
    clauses = ["status = 'active'"]
    params: list = []
    if verdict:
        clauses.append("risk_verdict = ?")
        params.append(verdict.upper())
    if max_price is not None:
        clauses.append("price_usd IS NOT NULL AND price_usd <= ?")
        params.append(max_price)
    if q:
        clauses.append("domain LIKE ?")
        params.append(f"%{q.lower()}%")
    sql = f"SELECT * FROM listings WHERE {' AND '.join(clauses)} ORDER BY created_at DESC"
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [serialize_listing(conn, r, viewer["id"] if viewer else None) for r in rows]


@router.get("/api/listings/mine")
def my_listings(user: dict = Depends(require_user)):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM listings WHERE seller_id = ? ORDER BY created_at DESC", (user["id"],)
        ).fetchall()
        return [serialize_listing(conn, r, user["id"]) for r in rows]


def _get_listing_or_404(conn, listing_id: int):
    row = conn.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
    if row is None:
        raise HTTPException(404, detail="Listing not found")
    return row


@router.get("/api/listings/{listing_id}")
def listing_detail(listing_id: int, request: Request):
    viewer = get_current_user(request)
    with get_conn() as conn:
        row = _get_listing_or_404(conn, listing_id)
        return serialize_listing(conn, row, viewer["id"] if viewer else None)


@router.post("/api/listings/{listing_id}/rescan")
async def rescan_listing(listing_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        row = _get_listing_or_404(conn, listing_id)
        if row["seller_id"] != user["id"]:
            raise HTTPException(403, detail="Only the seller can rescan this listing")
        domain = row["domain"]
    scan = await run_full_scan(domain)
    with get_conn() as conn:
        conn.execute(
            "UPDATE listings SET risk_score = ?, risk_verdict = ?, scan_json = ?, scanned_at = ? "
            "WHERE id = ?",
            (scan["score"], scan["verdict"], json.dumps(scan), now_iso(), listing_id),
        )
        row = conn.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
        return serialize_listing(conn, row, user["id"])


@router.post("/api/listings/{listing_id}/withdraw")
def withdraw_listing(listing_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        row = _get_listing_or_404(conn, listing_id)
        if row["seller_id"] != user["id"]:
            raise HTTPException(403, detail="Only the seller can withdraw this listing")
        if row["status"] != "active":
            raise HTTPException(409, detail=f"Listing is '{row['status']}', not active")
        conn.execute("UPDATE listings SET status = 'withdrawn' WHERE id = ?", (listing_id,))
        row = conn.execute("SELECT * FROM listings WHERE id = ?", (listing_id,)).fetchone()
        return serialize_listing(conn, row, user["id"])


# --------------------------------------------------------------------------
# offers
# --------------------------------------------------------------------------

def serialize_offer(conn, row, viewer_id: int) -> dict:
    d = dict(row)
    listing = conn.execute("SELECT * FROM listings WHERE id = ?", (d["listing_id"],)).fetchone()
    d["listing"] = serialize_listing(conn, listing, viewer_id)
    d["buyer"] = public_user(conn, d["buyer_id"])
    is_party = viewer_id in (d["buyer_id"], listing["seller_id"])
    if d["status"] == "accepted" and is_party:
        other_id = d["buyer_id"] if viewer_id == listing["seller_id"] else listing["seller_id"]
        other = conn.execute("SELECT email FROM users WHERE id = ?", (other_id,)).fetchone()
        d["counterpart_email"] = other["email"]
    del d["buyer_id"]
    return d


@router.post("/api/listings/{listing_id}/offers")
def make_offer(listing_id: int, body: OfferCreateBody, user: dict = Depends(require_user)):
    with get_conn() as conn:
        listing = _get_listing_or_404(conn, listing_id)
        if listing["status"] != "active":
            raise HTTPException(409, detail="This listing is not accepting offers")
        if listing["seller_id"] == user["id"]:
            raise HTTPException(400, detail="You can't make an offer on your own listing")
        cur = conn.execute(
            "INSERT INTO offers (listing_id, buyer_id, amount_usd, message, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (listing_id, user["id"], body.amount_usd, body.message, now_iso()),
        )
        row = conn.execute("SELECT * FROM offers WHERE id = ?", (cur.lastrowid,)).fetchone()
        return serialize_offer(conn, row, user["id"])


@router.get("/api/listings/{listing_id}/offers")
def offers_on_listing(listing_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        listing = _get_listing_or_404(conn, listing_id)
        if listing["seller_id"] != user["id"]:
            raise HTTPException(403, detail="Only the seller can view offers on this listing")
        rows = conn.execute(
            "SELECT * FROM offers WHERE listing_id = ? ORDER BY created_at DESC", (listing_id,)
        ).fetchall()
        return [serialize_offer(conn, r, user["id"]) for r in rows]


@router.get("/api/offers/mine")
def my_offers(user: dict = Depends(require_user)):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM offers WHERE buyer_id = ? ORDER BY created_at DESC", (user["id"],)
        ).fetchall()
        return [serialize_offer(conn, r, user["id"]) for r in rows]


def _get_offer_or_404(conn, offer_id: int):
    row = conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()
    if row is None:
        raise HTTPException(404, detail="Offer not found")
    return row


@router.get("/api/offers/{offer_id}")
def offer_detail(offer_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        row = _get_offer_or_404(conn, offer_id)
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (row["listing_id"],)).fetchone()
        if user["id"] not in (row["buyer_id"], listing["seller_id"]):
            raise HTTPException(403, detail="Not a party to this offer")
        return serialize_offer(conn, row, user["id"])


@router.post("/api/offers/{offer_id}/accept")
def accept_offer(offer_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        offer = _get_offer_or_404(conn, offer_id)
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (offer["listing_id"],)).fetchone()
        if listing["seller_id"] != user["id"]:
            raise HTTPException(403, detail="Only the seller can accept offers")
        if listing["status"] != "active":
            raise HTTPException(409, detail=f"Listing is '{listing['status']}', not active")
        if offer["status"] != "pending":
            raise HTTPException(409, detail=f"Offer is '{offer['status']}', not pending")
        ts = now_iso()
        conn.execute("UPDATE offers SET status = 'accepted', decided_at = ? WHERE id = ?", (ts, offer_id))
        conn.execute(
            "UPDATE offers SET status = 'rejected', decided_at = ? "
            "WHERE listing_id = ? AND id != ? AND status = 'pending'",
            (ts, listing["id"], offer_id),
        )
        conn.execute("UPDATE listings SET status = 'agreed' WHERE id = ?", (listing["id"],))
        row = conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()
        return serialize_offer(conn, row, user["id"])


@router.post("/api/offers/{offer_id}/reject")
def reject_offer(offer_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        offer = _get_offer_or_404(conn, offer_id)
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (offer["listing_id"],)).fetchone()
        if listing["seller_id"] != user["id"]:
            raise HTTPException(403, detail="Only the seller can reject offers")
        if offer["status"] != "pending":
            raise HTTPException(409, detail=f"Offer is '{offer['status']}', not pending")
        conn.execute(
            "UPDATE offers SET status = 'rejected', decided_at = ? WHERE id = ?", (now_iso(), offer_id)
        )
        row = conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()
        return serialize_offer(conn, row, user["id"])


@router.post("/api/offers/{offer_id}/withdraw")
def withdraw_offer(offer_id: int, user: dict = Depends(require_user)):
    with get_conn() as conn:
        offer = _get_offer_or_404(conn, offer_id)
        if offer["buyer_id"] != user["id"]:
            raise HTTPException(403, detail="Only the buyer can withdraw their own offer")
        if offer["status"] != "pending":
            raise HTTPException(409, detail=f"Offer is '{offer['status']}', not pending")
        conn.execute(
            "UPDATE offers SET status = 'withdrawn', decided_at = ? WHERE id = ?", (now_iso(), offer_id)
        )
        row = conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()
        return serialize_offer(conn, row, user["id"])


@router.post("/api/offers/{offer_id}/complete")
def complete_trade(offer_id: int, user: dict = Depends(require_user)):
    """Either party confirms the off-platform transfer + payment actually
    happened. This — not merely 'accepted' — is what unlocks ratings, since
    an agreement can still fall through before the domain actually moves."""
    with get_conn() as conn:
        offer = _get_offer_or_404(conn, offer_id)
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (offer["listing_id"],)).fetchone()
        if user["id"] not in (offer["buyer_id"], listing["seller_id"]):
            raise HTTPException(403, detail="Not a party to this trade")
        if offer["status"] != "accepted":
            raise HTTPException(409, detail=f"Offer is '{offer['status']}', not accepted")
        conn.execute("UPDATE offers SET status = 'completed' WHERE id = ?", (offer_id,))
        conn.execute("UPDATE listings SET status = 'sold' WHERE id = ?", (listing["id"],))
        row = conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()
        return serialize_offer(conn, row, user["id"])


# --------------------------------------------------------------------------
# ratings
# --------------------------------------------------------------------------

@router.post("/api/offers/{offer_id}/rate")
def rate_trade(offer_id: int, body: RateBody, user: dict = Depends(require_user)):
    with get_conn() as conn:
        offer = _get_offer_or_404(conn, offer_id)
        listing = conn.execute("SELECT * FROM listings WHERE id = ?", (offer["listing_id"],)).fetchone()
        if user["id"] not in (offer["buyer_id"], listing["seller_id"]):
            raise HTTPException(403, detail="Not a party to this trade")
        if offer["status"] != "completed":
            raise HTTPException(409, detail="Can only rate a completed trade")
        ratee_id = listing["seller_id"] if user["id"] == offer["buyer_id"] else offer["buyer_id"]
        try:
            conn.execute(
                "INSERT INTO ratings (offer_id, rater_id, ratee_id, stars, comment, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (offer_id, user["id"], ratee_id, body.stars, body.comment, now_iso()),
            )
        except Exception:
            raise HTTPException(409, detail="You already rated this trade")
        return {"ok": True}


# --------------------------------------------------------------------------
# public profile + admin verification badge
# --------------------------------------------------------------------------

@router.get("/api/users/{user_id}")
def user_profile(user_id: int):
    with get_conn() as conn:
        profile = public_user(conn, user_id)
        listings = conn.execute(
            "SELECT * FROM listings WHERE seller_id = ? AND status = 'active' ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        profile["active_listings"] = [serialize_listing(conn, r, None) for r in listings]
        return profile


@router.post("/api/admin/users/{user_id}/verify")
def verify_user(user_id: int, request: Request):
    admin_token = os.environ.get("ADMIN_TOKEN")
    if not admin_token:
        raise HTTPException(404, detail="Admin verification is not enabled on this server")
    if request.headers.get("X-Admin-Token") != admin_token:
        raise HTTPException(403, detail="Invalid admin token")
    with get_conn() as conn:
        cur = conn.execute("UPDATE users SET verified = 1 WHERE id = ?", (user_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, detail="User not found")
        return public_user(conn, user_id)
