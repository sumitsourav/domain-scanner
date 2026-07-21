"""Heuristic trademark-collision check.

There is no free, keyless trademark search API, so this flags the obvious
landmines: a famous brand name embedded in the label (containment) or one
edit away from it (typosquat). Results are a heuristic screen, not legal
advice — the UI links to USPTO/EUIPO search for confirmation.
"""

from __future__ import annotations

from typing import Any

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
    return {
        "status": "ok",
        "label": label,
        "exact_match": exact,
        "contains_brands": contains[:5],
        "typosquat_of": typosquats[:5],
        "conflict": conflict,
        "search_links": {
            "USPTO": f"https://tmsearch.uspto.gov/search/search-information?query={label}",
            "EUIPO": f"https://euipo.europa.eu/eSearch/#basic/1+1+1+1/50+50+50+50/{label}",
            "WIPO": f"https://branddb.wipo.int/en/similarname?q={label}",
        },
    }
