"""SQLite persistence layer.

Stdlib-only (sqlite3) — this is a small local app, an ORM would be more
ceremony than the schema warrants. One connection per request via a
context manager; SQLite handles concurrent readers fine and short-lived
writes don't need pooling at this scale.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "marketplace.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS listings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id    INTEGER NOT NULL REFERENCES users(id),
    domain       TEXT NOT NULL,
    price_usd    REAL,
    description  TEXT,
    status       TEXT NOT NULL DEFAULT 'active',  -- active | agreed | sold | withdrawn
    risk_score   INTEGER,
    risk_verdict TEXT,
    scan_json    TEXT,
    scanned_at   TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS offers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id  INTEGER NOT NULL REFERENCES listings(id),
    buyer_id    INTEGER NOT NULL REFERENCES users(id),
    amount_usd  REAL,
    message     TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending | accepted | rejected | withdrawn
    created_at  TEXT NOT NULL,
    decided_at  TEXT
);

CREATE TABLE IF NOT EXISTS ratings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    offer_id   INTEGER NOT NULL REFERENCES offers(id),
    rater_id   INTEGER NOT NULL REFERENCES users(id),
    ratee_id   INTEGER NOT NULL REFERENCES users(id),
    stars      INTEGER NOT NULL,
    comment    TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(offer_id, rater_id)
);

-- One row per domain (upserted on every scan) — the accumulated fingerprint
-- history that powers the "shares infrastructure with N previously-scanned
-- high-risk domains" signal in app/network_history.py. nameservers is a
-- sorted, comma-joined string (not JSON) so an exact-match SQL comparison
-- is order-independent without needing sqlite's JSON extension.
CREATE TABLE IF NOT EXISTS scans (
    domain       TEXT PRIMARY KEY,
    resolved_ip  TEXT,
    nameservers  TEXT,
    asn          TEXT,
    asn_name     TEXT,
    risk_score   INTEGER NOT NULL,
    risk_verdict TEXT NOT NULL,
    scanned_at   TEXT NOT NULL
);

-- Response cache for slow/flaky external checks (crt.sh, Wayback). Keyed by
-- (source, domain); payload is the check's JSON result. Powers both a
-- freshness cache and a stale-on-error fallback — see app/scan_cache.py.
CREATE TABLE IF NOT EXISTS check_cache (
    source     TEXT NOT NULL,
    domain     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (source, domain)
);

CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
CREATE INDEX IF NOT EXISTS idx_listings_seller ON listings(seller_id);
CREATE INDEX IF NOT EXISTS idx_offers_listing ON offers(listing_id);
CREATE INDEX IF NOT EXISTS idx_offers_buyer ON offers(buyer_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(resolved_ip);
CREATE INDEX IF NOT EXISTS idx_scans_ns ON scans(nameservers);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(risk_verdict);
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
