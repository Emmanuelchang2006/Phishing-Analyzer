from __future__ import annotations

from app.schemas.scan import KeywordDetectionResult, KeywordMatch

# Keyword → weight per category. Higher weight = stronger phishing signal.
PHISHING_KEYWORDS: dict[str, dict[str, int]] = {
    "urgency": {
        "urgent": 3,
        "immediately": 3,
        "within 24 hours": 4,
        "account suspended": 4,
        "act now": 3,
        "limited time": 2,
        "expire": 2,
        "expiring": 2,
        "expiry": 2,
        "last chance": 3,
        "final notice": 3,
        "warning": 2,
        "action required": 4,
        "attention required": 3,
    },
    "credential_theft": {
        "verify your account": 5,
        "confirm your identity": 4,
        "update your information": 3,
        "click here to login": 4,
        "reset your password": 3,
        "enter your password": 5,
        "enter your credentials": 5,
        "sign in to verify": 4,
        "confirm your email": 3,
        "validate your account": 4,
    },
    "financial": {
        "bank account": 3,
        "credit card": 3,
        "billing information": 3,
        "payment required": 3,
        "invoice attached": 4,
        "wire transfer": 4,
        "refund": 2,
        "tax refund": 3,
        "unusual activity": 3,
        "suspicious activity": 3,
        "unauthorized access": 4,
    },
    "authority": {
        "microsoft team": 3,
        "apple support": 3,
        "paypal security": 4,
        "government notice": 3,
        "irs": 3,
        "fbi": 3,
        "interpol": 3,
        "technical support": 2,
        "helpdesk": 1,
        "it department": 2,
        "security team": 2,
    },
    "delivery": {
        "package delivery": 2,
        "parcel notification": 2,
        "shipping update": 2,
        "tracking number": 1,
        "undelivered package": 3,
        "customs fees": 3,
        "delivery failed": 3,
    },
}


def _snippet(text: str, idx: int, window: int = 40) -> str:
    start = max(0, idx - window)
    end = min(len(text), idx + window)
    return text[start:end].replace("\n", " ").strip()


class KeywordDetectorService:
    """
    Scans text for phishing-associated keywords and phrases.

    Each match is weighted by its category and severity. The total weight
    feeds into the risk engine as an additive signal.
    """

    def detect(self, text: str) -> KeywordDetectionResult:
        if not text:
            return KeywordDetectionResult()

        lower_text = text.lower()
        matches: list[KeywordMatch] = []
        categories_seen: set[str] = set()
        seen_keywords: set[str] = set()

        for category, keywords in PHISHING_KEYWORDS.items():
            for keyword, weight in keywords.items():
                if keyword in seen_keywords:
                    continue
                idx = lower_text.find(keyword)
                if idx != -1:
                    matches.append(
                        KeywordMatch(
                            keyword=keyword,
                            category=category,
                            weight=weight,
                            context=_snippet(text, idx),
                        )
                    )
                    categories_seen.add(category)
                    seen_keywords.add(keyword)

        total_weight = sum(m.weight for m in matches)
        return KeywordDetectionResult(
            matches=matches,
            total_weight=total_weight,
            categories=sorted(categories_seen),
        )
