from __future__ import annotations

from app.schemas.scan import TyposquattingMatch, TyposquattingResult

# Known brand → canonical domain mapping
BRAND_DOMAINS: dict[str, str] = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "yahoo": "yahoo.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "citibank": "citibank.com",
    "hsbc": "hsbc.com",
    "icloud": "icloud.com",
    "outlook": "outlook.com",
    "office": "office.com",
    "onedrive": "onedrive.com",
    "adobe": "adobe.com",
    "docusign": "docusign.com",
    "zoom": "zoom.us",
    "slack": "slack.com",
    "stripe": "stripe.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
}

MAX_DISTANCE = 2


def _levenshtein(a: str, b: str) -> int:
    """Pure-Python Levenshtein distance — no external dependencies."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


class TyposquattingService:
    """
    Detects domain names that closely resemble known brand domains.

    Uses Levenshtein edit distance on the second-level domain (SLD) portion
    of the scanned domain against a curated brand list. A distance of 1 or 2
    edits is the threshold most typosquatting campaigns operate within.
    """

    def check(self, domain: str) -> TyposquattingResult:
        if not domain:
            return TyposquattingResult(checked_domain=domain)

        # Work on the SLD only (strip TLD and www)
        clean = domain.lower().lstrip("www.").lstrip("www.")
        parts = clean.split(".")
        sld = parts[-2] if len(parts) >= 2 else parts[0]

        matches: list[TyposquattingMatch] = []
        for brand, brand_domain in BRAND_DOMAINS.items():
            if sld == brand:
                continue  # exact match — not typosquatting
            dist = _levenshtein(sld, brand)
            if 0 < dist <= MAX_DISTANCE:
                sim = 1.0 - dist / max(len(sld), len(brand))
                matches.append(
                    TyposquattingMatch(
                        brand=brand,
                        brand_domain=brand_domain,
                        distance=dist,
                        similarity=round(sim, 3),
                    )
                )

        # Sort by edit distance, then by descending similarity
        matches.sort(key=lambda m: (m.distance, -m.similarity))

        return TyposquattingResult(
            is_typosquatting=len(matches) > 0,
            matches=matches[:5],
            checked_domain=domain,
        )
