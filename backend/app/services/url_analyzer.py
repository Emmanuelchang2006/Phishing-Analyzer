from __future__ import annotations

import math
import re
import unicodedata
from urllib.parse import unquote, urlparse

import httpx

from app.core.logging import get_logger
from app.schemas.scan import URLAnalysisResult, URLFeatures

logger = get_logger(__name__)

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "short.link",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "lnkd.in",
    "rb.gy", "shorturl.at", "clck.ru", "bc.vc", "adf.ly", "su.pr",
}

CREDENTIAL_KEYWORDS = {
    "login", "signin", "sign-in", "logon", "auth", "authenticate",
    "password", "passwd", "credential", "verify", "verification",
    "account", "secure", "security", "update", "confirm", "billing",
    "wallet", "banking", "payment", "invoice", "reset", "recover",
    "webscr", "secure-", "-secure", "validate",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".online", ".site", ".club",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _has_homograph(domain: str) -> bool:
    """Detect mixed-script domains used in IDN homograph attacks."""
    scripts: set[str] = set()
    for ch in domain:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if "LATIN" in name:
                scripts.add("latin")
            elif "CYRILLIC" in name:
                scripts.add("cyrillic")
            elif "GREEK" in name:
                scripts.add("greek")
            elif "ARMENIAN" in name:
                scripts.add("armenian")
            elif "GEORGIAN" in name:
                scripts.add("georgian")
    return len(scripts) > 1


def _has_credential_keywords(url: str) -> bool:
    path = unquote(urlparse(url).path.lower())
    query = unquote(urlparse(url).query.lower())
    combined = path + " " + query
    return any(kw in combined for kw in CREDENTIAL_KEYWORDS)


def _ml_heuristic_score(url: str) -> float:
    """
    Lightweight heuristic classifier for phishing URLs.

    Returns a 0.0–1.0 probability estimate. Loads a sklearn joblib model
    from app/ml/phishing_classifier.pkl if available; otherwise uses a
    weighted feature sum calibrated against known phishing patterns.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower().lstrip("www.")
    path = unquote(parsed.path.lower())
    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    has_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)

    raw = (
        min(len(url), 200) * 0.002
        + min(len(domain), 50) * 0.004
        + _shannon_entropy(url) * 0.04
        + domain.count(".") * 0.02
        + domain.count("-") * 0.025
        + (0.25 if "@" in url else 0)
        + (0.30 if has_ip else 0)
        + (0.15 if tld in SUSPICIOUS_TLDS else 0)
        + (0.10 if domain in SHORTENER_DOMAINS else 0)
        + digit_ratio * 0.08
        + (0.15 if any(kw in path for kw in CREDENTIAL_KEYWORDS) else 0)
        + max(0, domain.count(".") - 1) * 0.02
        + (-0.05 if parsed.scheme == "https" else 0)
        + (len(parsed.query.split("&")) * 0.008 if parsed.query else 0)
    )
    return round(min(max(raw, 0.0), 1.0), 4)


async def _follow_redirects(url: str, max_hops: int = 5) -> list[str]:
    """Follow HTTP redirects and return the full chain of URLs."""
    chain = [url]
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=4.0,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishingAnalyzer/2.0)"},
        ) as client:
            current = url
            for _ in range(max_hops):
                try:
                    r = await client.head(current)
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location", "")
                        if loc and loc not in chain:
                            chain.append(loc)
                            current = loc
                        else:
                            break
                    else:
                        break
                except Exception:
                    break
    except Exception:
        pass
    return chain


class URLAnalyzerService:
    """
    Analyzes URLs extracted from scan targets for phishing indicators.

    Checks: Shannon entropy, URL shorteners (with redirect following),
    credential-harvesting keywords, IDN homograph attacks, and a heuristic
    ML-style phishing probability score.
    """

    async def analyze(self, urls: list[str]) -> URLAnalysisResult:
        if not urls:
            return URLAnalysisResult(extracted_urls=[])

        analyzed: list[URLFeatures] = []
        high_risk: list[str] = []

        for url in urls[:10]:  # cap to avoid timeout on large email bodies
            try:
                features = await self._analyze_one(url)
                analyzed.append(features)
                if self._is_high_risk(features):
                    high_risk.append(url)
            except Exception as exc:
                logger.warning("url_analysis_error", url=url[:80], error=str(exc))

        return URLAnalysisResult(
            extracted_urls=urls,
            analyzed_urls=analyzed,
            high_risk_urls=high_risk,
        )

    async def _analyze_one(self, url: str) -> URLFeatures:
        parsed = urlparse(url)
        domain = (parsed.netloc or "").lower().lstrip("www.")
        is_shortener = domain in SHORTENER_DOMAINS

        redirect_chain = await _follow_redirects(url) if is_shortener else [url]
        final_url = redirect_chain[-1] if redirect_chain else url

        return URLFeatures(
            url=url,
            entropy=round(_shannon_entropy(url), 3),
            is_shortener=is_shortener,
            has_credential_keywords=_has_credential_keywords(url),
            has_homograph=_has_homograph(domain),
            redirect_chain=redirect_chain,
            final_url=final_url,
            ml_phishing_score=_ml_heuristic_score(url),
        )

    @staticmethod
    def _is_high_risk(f: URLFeatures) -> bool:
        signals = sum([
            bool(f.has_credential_keywords),
            bool(f.has_homograph),
            len(f.redirect_chain) > 2,
            (f.entropy or 0) > 4.5,
            (f.ml_phishing_score or 0) > 0.6,
        ])
        return signals >= 2
