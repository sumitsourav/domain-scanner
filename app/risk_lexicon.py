"""Shared spam/scam keyword lexicon, used by both the Wayback history scan
(app/checks/history.py, matched against archived URL strings) and the live
page-content scan (app/checks/live_content.py, matched against the page's
current text). One list so the two checks can't drift apart on what counts
as "risky."

Verticals with outsized reputation damage. Word-ish boundaries to avoid
false hits like "class" -> "cialis" style substring accidents.
"""

from __future__ import annotations

import re

RISK_LEXICON = {
    "pharma": r"viagra|cialis|levitra|xanax|valium|tramadol|pharmacy|pills?",
    "gambling": r"casino|poker|slots?|betting|roulette|jackpot",
    "adult": r"porn|xxx|escorts?|adult-?dating|camgirls?",
    "counterfeit": r"replica|knock-?off|fake-?(watches|bags|designer)",
    "predatory-finance": r"payday-?loans?|quick-?cash|forex-?signals?|binary-?options?",
    "crypto-scam": r"free-?bitcoin|crypto-?(giveaway|doubler)|airdrops?-?free",
    "malware-ish": r"keygen|cracked?-?(software|apk)|serial-?key|warez",
    "seo-spam": r"buy-?backlinks?|cheap-?seo|link-?farm",
}
PATTERNS = {cat: re.compile(rx, re.IGNORECASE) for cat, rx in RISK_LEXICON.items()}
