"""Password hashing and cookie-session auth.

Stdlib-only: PBKDF2-HMAC-SHA256 (OWASP's minimum-iteration recommendation)
for passwords instead of pulling in bcrypt/argon2, and opaque random
session tokens stored server-side instead of JWTs — server-side sessions
can be revoked (logout actually invalidates something); a JWT can't be
without an extra denylist table anyway, so it buys nothing here.

Not hardened for production internet exposure: no rate limiting on
login/signup, no email verification, no CSRF token (relies on the
session cookie's SameSite=Lax). Fine for a local/trusted-network app;
call it out before deploying this publicly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, Request

from .db import get_conn

PBKDF2_ITERATIONS = 600_000
SESSION_COOKIE = "session"
SESSION_TTL_DAYS = 30


def hash_password(password: str) -> tuple[str, str]:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(digest.hex(), hash_hex)


def create_session(user_id: int) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires.isoformat()),
        )
    return token, expires


def destroy_session(token: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def _user_for_token(token: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute(
            """SELECT u.id, u.email, u.display_name, u.verified, s.expires_at
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ?""",
            (token,),
        ).fetchone()
    if row is None:
        return None
    expires = datetime.fromisoformat(row["expires_at"])
    if expires < datetime.now(timezone.utc):
        destroy_session(token)
        return None
    return dict(row)


def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return _user_for_token(token)


def require_user(request: Request) -> dict:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(401, detail="Sign in required")
    return user
