# Domain Risk Scanner — *Available ≠ Safe*

A domain can be free to register but toxic: prior spam use, blacklist listings,
scammy history, or trademark landmines. This app scans a candidate domain across
spam blacklists, prior-use archives, trademark heuristics, and email-reputation
signals, then hands you a single **0–100 risk score** before you buy.

It also includes a **P2P marketplace** for reselling domains with that risk
report attached to every listing — see [Marketplace](#marketplace) below.

## Run it

```sh
./run.sh          # creates .venv on first run, then serves http://localhost:8000
```

Or manually:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload
```

Open <http://localhost:8000>, type a domain, hit **Scan**.
API: `GET /api/scan?domain=example.com` returns the full JSON report.

The marketplace lives at <http://localhost:8000/marketplace> and shares the
same process/port — no separate server to run. Its SQLite database is created
on first startup at `data/marketplace.db` (gitignored).

## Configuration

Two optional secrets, both env vars, both gate a feature that simply reports
itself as "not enabled" when unset — nothing breaks without them:

```sh
cp .env.example .env    # then fill in what you want
```

| Var | Enables | Get one |
|---|---|---|
| `ABUSECH_AUTH_KEY` | URLhaus malware-hosting check | <https://auth.abuse.ch/> (free) |
| `ADMIN_TOKEN` | `POST /api/admin/users/{id}/verify` — toggles a seller's verified badge | pick any long random string |

`app/main.py` loads `.env` via `python-dotenv` before anything else runs, so
`./run.sh` picks it up automatically — no need to export the vars in your
shell. `.env` is gitignored; `.env.example` is the checked-in template.

## What it checks

| Check | Source | Signal | Keyless? |
|---|---|---|---|
| Availability | RDAP (`rdap.org` bootstrap → authoritative registry) | available vs. registered, registrar, age, expiry | yes |
| Spam blacklists | Spamhaus DBL, SURBL, URIBL (domain); Spamhaus ZEN, Barracuda (resolved IP) | listings that make mail servers reject you on day one | yes |
| Malware hosting | URLhaus (abuse.ch) | domains that have directly hosted malware payloads or C2 infrastructure | **no** — set `ABUSECH_AUTH_KEY` |
| Mail infrastructure | live MX / SPF / DMARC via DNS | measured mail setup, not a guess — flags a `+all` SPF (accepts mail from any sender) | yes |
| Prior-use history | Wayback Machine CDX API | first/last archived year, activity timeline, drop-catch churn, spam/scam keywords in up to 800 archived URLs | yes |
| Certificate history | Certificate Transparency logs (crt.sh) | subdomains and date range seen in every publicly-trusted TLS cert ever issued — reveals prior operator footprint even where Wayback never crawled | yes |
| Trademark screen | offline heuristic vs. ~120 famous marks + ~1800 high-traffic domains | exact / containment / distance-1 typosquat against famous brands; typosquat-only against a broader popularity corpus (a different risk: traffic hijacking, not trademark) | yes |
| Reputation priors | offline heuristic (Spamhaus/Interisle TLD abuse patterns; a small premium-registrar allowlist) | TLD abuse-rate tier (`.top`, `.xyz`-style new gTLDs vs. legacy); registrar trust is informational-only — see [Known quirks](#known-quirks) for why there's no "risky registrar" list | yes |
| Email deliverability | derived | blacklist status + SPF + reputation history rolled into a GOOD / WATCH / POOR verdict | yes |

To enable the optional URLhaus malware check, get a free key at <https://auth.abuse.ch/>
and run `ABUSECH_AUTH_KEY=xxxx ./run.sh`. Without it, that card just reports "not enabled."

## Scoring

Additive, capped at 100, with a per-factor evidence breakdown in the response:
Spamhaus DBL +45 · URLhaus malware hosting +35 · SURBL/URIBL +30 · IP lists +15 ·
risky archive content +25–40 · famous-brand collision +25–30 ·
popular-domain typosquat +15 · permissive SPF (`+all`) +15 ·
high-abuse TLD +10 · drop-catch churn +10.

Bands: **0–19 LOW · 20–44 MODERATE · 45–69 HIGH · 70+ SEVERE.**
Sources that time out are reported as *coverage gaps*, never silently counted as
clean. Certificate Transparency and registrar trust are informational only
(they don't move the score) — subdomain footprints and registrar choice
correlate with prior use, not cleanly with risk direction.

## Known quirks

- **Spamhaus / URIBL** refuse queries from well-known public resolvers (1.1.1.1,
  8.8.8.8) — the app detects the refusal sentinels and reports those lists as
  UNKNOWN instead of clean.
- **crt.sh** is a free community service that is frequently overloaded (502/504
  or timeouts are common, especially for high-traffic domains). Treated as a
  coverage gap, never as "no certificates."
- **Mail infrastructure lookups deliberately use public DNS** (1.1.1.1 / 9.9.9.9 /
  8.8.8.8) rather than your system resolver — some ISP/router DNS proxies
  silently truncate or REFUSE multi-record TXT answers, which would otherwise
  be mistaken for "no SPF record configured." This is safe for plain MX/TXT
  lookups (unlike the DNSBL zones above, they aren't subject to anti-abuse
  blocking of public resolvers).
- **No "risky registrar" list, on purpose.** `app/checks/reputation.py` only
  ever gives a positive signal (a small allowlist of registrars documented as
  corporate/brand-protection specialists, e.g. MarkMonitor). Naming specific
  companies as abuse-prone in scoring code asserts a reputational claim this
  app has no live way to verify, and any registrar's abuse profile can shift
  entirely under new ownership or policy — unlike a DNSBL listing, which is a
  live, third-party-maintained verdict we're just relaying.
- **TLD abuse tiers are a static, hand-maintained prior**, not a live feed —
  based on repeated findings in Spamhaus's "World's Most Abused TLDs" and
  Interisle's Cybercrime Supply Chain reports. Weighted modestly (+5/+10)
  since it's a prior about the TLD in general, not a verdict on this domain.

## Marketplace

A P2P domain reselling marketplace built on top of the scanner, at `/marketplace`.
Three trust mechanisms, no in-app payments:

1. **Risk score gate** — every listing is created by running the exact same
   scan pipeline as `/api/scan`, cached on the listing (`GET /api/listings/{id}`
   includes the full report) and rerunnable via a "Rescan" button. Full
   disclosure, not a score threshold — a MODERATE-risk domain can still be
   listed, but never unscanned.
2. **Seller reputation** — 1–5 star ratings, unlocked only once a trade is
   explicitly marked *completed* (not merely "offer accepted" — an agreement
   can still fall through before the off-platform transfer happens).
3. **Manual verification badge** — an operator-toggled "✓ verified" badge via
   `POST /api/admin/users/{id}/verify` with header `X-Admin-Token`, gated by
   the `ADMIN_TOKEN` env var (same pattern as `ABUSECH_AUTH_KEY` — unset means
   disabled, returns 404).

**Trade flow:** sign up → list a domain (auto-scanned) → buyers browse/filter
by risk verdict and price → buyer submits an offer → seller accepts (this
reveals both parties' emails so they can finalize the domain transfer and
payment off-platform — registrar push, escrow.com, wire, whatever they agree)
→ either party marks the trade *completed* once the transfer actually
happened → both sides can now rate each other.

**No money moves through this app.** Payment/escrow is deliberately out of
scope — real payment handling needs a licensed processor (Stripe Connect,
Escrow.com) and carries money-transmission compliance weight well beyond a
local tool. See Roadmap.

**Stack:** stdlib `sqlite3` (no ORM — five tables don't need one), PBKDF2-HMAC-SHA256
password hashing (`hashlib`, no bcrypt dependency), opaque server-side session
tokens in an httponly/SameSite=Lax cookie (revocable on logout, unlike a JWT).
Not hardened for public internet exposure: no rate limiting on login/signup,
no email verification, no CSRF token beyond the cookie's SameSite policy. Fine
for local/trusted-network use; harden before deploying publicly.

## Roadmap

- Additional keyed providers behind env vars: Google Safe Browsing, VirusTotal,
  SecurityTrails passive DNS
- Real trademark search (USPTO TSDR API key)
- Bulk CSV scanning for portfolio triage, result caching/persistence
- Marketplace: escrow-backed payments via a licensed processor, email
  verification, rate limiting, CSRF tokens, full-text search

*Heuristic screening tool — not legal advice, not a deliverability guarantee.*
