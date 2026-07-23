"""Heuristic trademark-collision and traffic-hijack typosquat check.

Two layers:
  1. Trademark collision — a famous brand embedded in the label
     (containment) or one edit away (typosquat), against a small curated
     list. No free, keyless trademark search API exists, so this is a
     heuristic screen, not legal advice — the UI links to USPTO/EUIPO
     search for confirmation.
  2. General traffic-hijack typosquat — one edit away from any of ~1800
     high-traffic domains (see app/popular_labels.py), typosquat-only
     (never containment, which would be far too noisy at this size). This
     targets a different risk than trademark law: scammers typosquat any
     popular destination to steal traffic/credentials, brand-owner or not.
     Only checked when no trademark-layer hit already fired.
"""

from __future__ import annotations

from typing import Any

from ..popular_labels import POPULAR_LABELS

FAMOUS_BRANDS = [
    # tech
    "google", "youtube", "facebook", "instagram", "whatsapp", "microsoft",
    "windows", "xbox", "apple", "iphone", "ipad", "icloud", "amazon", "alexa",
    "netflix", "spotify", "twitter", "tiktok", "snapchat", "linkedin",
    "paypal", "venmo", "stripe", "shopify", "ebay", "etsy", "airbnb", "uber",
    "lyft", "tesla", "nvidia", "intel", "samsung", "huawei", "xiaomi", "sony",
    "playstation", "nintendo", "adobe", "photoshop", "oracle", "salesforce",
    "zoom", "slack", "dropbox", "github", "reddit", "discord", "twitch",
    "openai", "chatgpt", "anthropic", "claude", "gemini", "android", "chrome",
    "gmail", "outlook", "office365", "verizon", "comcast", "tmobile",
    # finance
    "visa", "mastercard", "amex", "chase", "citibank", "wellsfargo",
    "goldman", "fidelity", "vanguard", "coinbase", "binance", "robinhood",
    "westernunion", "moneygram", "revolut", "barclays", "hsbc", "santander",
    # consumer / retail
    "nike", "adidas", "puma", "reebok", "gucci", "prada", "chanel", "dior",
    "louisvuitton", "hermes", "rolex", "cartier", "tiffany", "zara", "ikea",
    "walmart", "target", "costco", "starbucks", "mcdonalds", "burgerking",
    "cocacola", "pepsi", "nestle", "loreal", "sephora", "lego", "disney",
    "marvel", "pixar", "warner", "spotify", "pfizer", "moderna", "fedex",
    "dhl", "ups", "usps", "toyota", "honda", "ford", "bmw", "mercedes",
    "porsche", "ferrari", "boeing", "airbus", "marriott", "hilton",
]
_BRANDS = sorted(set(b for b in FAMOUS_BRANDS if len(b) >= 4), key=len, reverse=True)

# Popular-domain corpus (see app/popular_labels.py) minus anything already in
# the curated brand list, so a hit is reported once, under one label.
_POPULAR = sorted(set(POPULAR_LABELS) - set(_BRANDS))


def _levenshtein_leq1(a: str, b: str) -> bool:
    """True if edit distance between a and b is exactly 1 (cheap two-pointer)."""
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = diffs = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            diffs += 1
            if diffs > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return True


def check_trademark(domain: str) -> dict[str, Any]:
    label = domain.split(".")[0]

    exact = None
    contains: list[str] = []
    typosquats: list[str] = []

    for brand in _BRANDS:
        if label == brand:
            exact = brand
        elif brand in label:
            contains.append(brand)
        elif _levenshtein_leq1(label, brand):
            typosquats.append(brand)

    conflict = bool(exact or contains or typosquats)

    # Broader traffic-hijack check: typosquat-only (no containment — the
    # corpus is too big and too generic for containment to stay low-noise)
    # against ~1800 high-traffic domains. Skipped entirely if a famous-brand
    # hit already fired, so the same collision is never reported twice.
    popular_typosquat = None
    if not conflict:
        for site in _POPULAR:
            if _levenshtein_leq1(label, site):
                popular_typosquat = site
                break

    return {
        "status": "ok",
        "label": label,
        "exact_match": exact,
        "contains_brands": contains[:5],
        "typosquat_of": typosquats[:5],
        "popular_typosquat_of": popular_typosquat,
        "conflict": conflict or bool(popular_typosquat),
        "search_links": {
            "USPTO": f"https://tmsearch.uspto.gov/search/search-information?query={label}",
            "EUIPO": f"https://euipo.europa.eu/eSearch/#basic/1+1+1+1/50+50+50+50/{label}",
            "WIPO": f"https://branddb.wipo.int/en/similarname?q={label}",
        },
    }
