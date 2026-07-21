# Domain Risk Scanner — *Available ≠ Safe*

A domain can be free to register but toxic: prior spam use, blacklist listings,
scammy history, or trademark landmines. This app scans a candidate domain across
spam blacklists, prior-use archives, trademark heuristics, and email-reputation
signals, then hands you a single **0–100 risk score** before you buy.

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

## What it checks

| Check | Source | Signal | Keyless? |
|---|---|---|---|
| Availability | RDAP (`rdap.org` bootstrap → authoritative registry) | available vs. registered, registrar, age, expiry | yes |
| Spam blacklists | Spamhaus DBL, SURBL, URIBL (domain); Spamhaus ZEN, Barracuda (resolved IP) | listings that make mail servers reject you on day one | yes |
| Malware hosting | URLhaus (abuse.ch) | domains that have directly hosted malware payloads or C2 infrastructure | **no** — set `ABUSECH_AUTH_KEY` |
| Mail infrastructure | live MX / SPF / DMARC via DNS | measured mail setup, not a guess — flags a `+all` SPF (accepts mail from any sender) | yes |
| Prior-use history | Wayback Machine CDX API | first/last archived year, activity timeline, drop-catch churn, spam/scam keywords in up to 800 archived URLs | yes |
| Certificate history | Certificate Transparency logs (crt.sh) | subdomains and date range seen in every publicly-trusted TLS cert ever issued — reveals prior operator footprint even where Wayback never crawled | yes |
| Trademark screen | offline heuristic vs. ~120 famous marks | exact / containment / distance-1 typosquat collisions, with USPTO · EUIPO · WIPO search links | yes |
| Email deliverability | derived | blacklist status + SPF + reputation history rolled into a GOOD / WATCH / POOR verdict | yes |

To enable the optional URLhaus malware check, get a free key at <https://auth.abuse.ch/>
and run `ABUSECH_AUTH_KEY=xxxx ./run.sh`. Without it, that card just reports "not enabled."

## Scoring

Additive, capped at 100, with a per-factor evidence breakdown in the response:
Spamhaus DBL +45 · URLhaus malware hosting +35 · SURBL/URIBL +30 · IP lists +15 ·
risky archive content +25–40 · famous-brand collision +25–30 ·
permissive SPF (`+all`) +15 · drop-catch churn +10.

Bands: **0–19 LOW · 20–44 MODERATE · 45–69 HIGH · 70+ SEVERE.**
Sources that time out are reported as *coverage gaps*, never silently counted as
clean. Certificate Transparency is informational only (subdomain footprints
correlate with prior use, not with risk direction) and isn't scored.

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

## Roadmap

- Additional keyed providers behind env vars: Google Safe Browsing, VirusTotal,
  SecurityTrails passive DNS
- Real trademark search (USPTO TSDR API key)
- Bulk CSV scanning for portfolio triage, result caching/persistence

*Heuristic screening tool — not legal advice, not a deliverability guarantee.*
