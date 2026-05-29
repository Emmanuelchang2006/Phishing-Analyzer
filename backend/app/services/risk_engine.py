from __future__ import annotations

from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.schemas.scan import (
    EmailAuthResult,
    KeywordDetectionResult,
    RiskLevel,
    RiskScore,
    ThreatIntelResult,
    TyposquattingResult,
    URLAnalysisResult,
    WhoisResult,
)

logger = get_logger(__name__)


@dataclass
class RiskContext:
    """All inputs the risk engine needs to compute a score."""

    threat_intel: list[ThreatIntelResult] = field(default_factory=list)
    whois: WhoisResult | None = None
    email_auth: EmailAuthResult | None = None
    typosquatting: TyposquattingResult | None = None
    url_analysis: URLAnalysisResult | None = None
    keywords: KeywordDetectionResult | None = None


class RiskEngine:
    """
    Aggregates multi-source threat intelligence into a single risk score.

    Scoring model (max 100 points):
    ┌─────────────────────────────────┬────────┐
    │ Signal                          │ Points │
    ├─────────────────────────────────┼────────┤
    │ VT malicious detections (≥5)    │  40    │
    │ VT malicious detections (1–4)   │  25    │
    │ VT suspicious detections only   │  15    │
    │ VT community reputation ≤ -50   │  15    │
    │ VT community reputation ≤ -10   │   8    │
    │ AbuseIPDB score ≥ 80            │  30    │
    │ AbuseIPDB score 25–79           │  15    │
    │ AbuseIPDB score 5–24            │   8    │
    │ AbuseIPDB is TOR exit node      │  20    │
    │ Domain registered < 7 days      │  30    │
    │ Domain registered < 30 days     │  20    │
    │ Domain registered < 90 days     │  10    │
    │ SPF fail or none                │  10    │
    │ DMARC none/fail                 │  10    │
    │ From ≠ Reply-To domain          │  15    │
    │ DKIM fail                       │   5    │
    │ Typosquatting detected          │  20    │
    │ Homograph attack (IDN)          │  25    │
    │ Credential keywords in URL      │  10    │
    │ High URL entropy (> 4.5)        │  10    │
    │ URL shortener with redirects    │  10    │
    │ ML phishing score > 0.8         │  20    │
    │ ML phishing score 0.6–0.8       │  10    │
    │ Keyword weight ≥ 10             │  15    │
    │ Keyword weight 5–9              │   8    │
    └─────────────────────────────────┴────────┘

    Floor: TOR exit nodes are always at least SUSPICIOUS (score ≥ 25).
    Scores are capped at 100. Risk levels:
      0–24:   CLEAN
      25–74:  SUSPICIOUS
      75–100: MALICIOUS
    """

    def compute(self, ctx: RiskContext) -> RiskScore:
        score = 0
        factors: list[str] = []

        score, factors = self._score_threat_intel(ctx.threat_intel, score, factors)
        score, factors = self._score_whois(ctx.whois, score, factors)
        score, factors = self._score_email_auth(ctx.email_auth, score, factors)
        score, factors = self._score_typosquatting(ctx.typosquatting, score, factors)
        score, factors = self._score_url_analysis(ctx.url_analysis, score, factors)
        score, factors = self._score_keywords(ctx.keywords, score, factors)

        # TOR exit nodes always warrant at least SUSPICIOUS
        tor_detected = any(
            r.raw_data is not None and r.raw_data.get("is_tor")
            for r in ctx.threat_intel
            if r.error is None
        )
        if tor_detected and score < 25:
            score = 25
            factors.append("Score raised to SUSPICIOUS floor: confirmed TOR exit node")

        score = min(score, 100)
        level = self._score_to_level(score)

        active_sources = sum(1 for r in ctx.threat_intel if r.error is None)
        has_whois = ctx.whois is not None and ctx.whois.domain_age_days is not None
        has_email_auth = ctx.email_auth is not None and (
            ctx.email_auth.spf_status is not None or ctx.email_auth.dmarc_status is not None
        )
        total_possible = (
            len(ctx.threat_intel)
            + (1 if ctx.whois else 0)
            + (1 if ctx.email_auth else 0)
        )
        total_successful = (
            active_sources + (1 if has_whois else 0) + (1 if has_email_auth else 0)
        )
        confidence = round(total_successful / max(total_possible, 1), 2)

        if not factors:
            factors = ["No threat indicators detected across active intelligence sources"]

        logger.info(
            "risk_score_computed",
            score=score,
            level=level,
            confidence=confidence,
            factor_count=len(factors),
        )

        return RiskScore(
            score=score,
            level=level,
            confidence=confidence,
            contributing_factors=factors,
        )

    # ── Scoring sub-methods ───────────────────────────────────────────────────

    @staticmethod
    def _score_threat_intel(
        results: list[ThreatIntelResult],
        score: int,
        factors: list[str],
    ) -> tuple[int, list[str]]:
        for result in results:
            if result.error or result.raw_data is None:
                continue

            source_label = result.source.replace("_", " ").title()

            if "virustotal" in result.source:
                malicious: int = result.raw_data.get("malicious", 0)
                suspicious: int = result.raw_data.get("suspicious", 0)
                total: int = result.raw_data.get("total_engines", 0)
                reputation = result.raw_data.get("reputation")

                if malicious >= 5:
                    score += 40
                    factors.append(f"{source_label}: {malicious}/{total} engines flagged as MALICIOUS")
                elif malicious >= 1:
                    score += 25
                    factors.append(f"{source_label}: {malicious}/{total} engines flagged as malicious")
                elif suspicious >= 1:
                    score += 15
                    factors.append(f"{source_label}: {suspicious}/{total} engines flagged as suspicious")

                if reputation is not None and isinstance(reputation, (int, float)):
                    rep = int(reputation)
                    if rep <= -50:
                        score += 15
                        factors.append(f"{source_label}: very negative community reputation ({rep:+d})")
                    elif rep <= -10:
                        score += 8
                        factors.append(f"{source_label}: negative community reputation ({rep:+d})")

            elif result.source == "abuseipdb":
                confidence: int = result.raw_data.get("abuse_confidence_score", 0)
                reports: int = result.raw_data.get("total_reports", 0)
                is_tor: bool = result.raw_data.get("is_tor", False)

                if is_tor:
                    score += 20
                    factors.append("AbuseIPDB: IP is a TOR exit node")

                if confidence >= 80:
                    score += 30
                    factors.append(f"AbuseIPDB: {confidence}% abuse confidence ({reports} reports)")
                elif confidence >= 25:
                    score += 15
                    factors.append(f"AbuseIPDB: {confidence}% abuse confidence ({reports} reports)")
                elif confidence >= 5:
                    score += 8
                    factors.append(f"AbuseIPDB: {confidence}% abuse confidence ({reports} reports) — low confidence")

        return score, factors

    @staticmethod
    def _score_whois(
        whois: WhoisResult | None,
        score: int,
        factors: list[str],
    ) -> tuple[int, list[str]]:
        if not whois or whois.domain_age_days is None:
            return score, factors

        age = whois.domain_age_days

        if age < 7:
            score += 30
            factors.append(f"WHOIS: Domain registered {age} day(s) ago — extremely suspicious")
        elif age < 30:
            score += 20
            factors.append(f"WHOIS: Domain registered {age} days ago — recently registered")
        elif age < 90:
            score += 10
            factors.append(f"WHOIS: Domain registered {age} days ago — relatively new")

        return score, factors

    @staticmethod
    def _score_email_auth(
        auth: EmailAuthResult | None,
        score: int,
        factors: list[str],
    ) -> tuple[int, list[str]]:
        if not auth:
            return score, factors

        if auth.domain_mismatch:
            score += 15
            factors.append(
                f"Email: From domain ({auth.from_domain}) != Reply-To domain "
                f"({auth.reply_to_domain}) — common phishing indicator"
            )

        if auth.spf_status in ("fail", "none"):
            score += 10
            label = "no SPF record" if auth.spf_status == "none" else "SPF check failed"
            factors.append(f"Email auth: {label} for {auth.from_domain}")
        elif auth.spf_status == "softfail":
            score += 5
            factors.append(f"Email auth: SPF softfail for {auth.from_domain}")

        if auth.dmarc_status in ("fail", "none"):
            score += 10
            label = "no DMARC policy" if auth.dmarc_status == "none" else "DMARC check failed"
            factors.append(f"Email auth: {label} for {auth.from_domain}")

        if auth.dkim_status == "fail":
            score += 5
            factors.append(f"Email auth: DKIM signature invalid for {auth.from_domain}")

        return score, factors

    @staticmethod
    def _score_typosquatting(
        typo: TyposquattingResult | None,
        score: int,
        factors: list[str],
    ) -> tuple[int, list[str]]:
        if not typo or not typo.is_typosquatting or not typo.matches:
            return score, factors

        best = typo.matches[0]
        score += 20
        factors.append(
            f"Typosquatting: '{typo.checked_domain}' closely resembles '{best.brand_domain}' "
            f"(edit distance {best.distance}, {best.similarity:.0%} similar)"
        )
        return score, factors

    @staticmethod
    def _score_url_analysis(
        ua: URLAnalysisResult | None,
        score: int,
        factors: list[str],
    ) -> tuple[int, list[str]]:
        if not ua:
            return score, factors

        for feat in ua.analyzed_urls:
            if feat.has_homograph:
                score += 25
                factors.append(f"IDN homograph attack: mixed Unicode scripts in domain of {feat.url[:60]}")

            if feat.has_credential_keywords:
                score += 10
                factors.append(f"Credential-harvesting keywords in URL path: {feat.url[:60]}")

            if feat.entropy is not None and feat.entropy > 4.5:
                score += 10
                factors.append(f"High URL entropy ({feat.entropy:.2f}) suggests obfuscation or encoded payload")

            if feat.is_shortener and len(feat.redirect_chain) > 1:
                score += 10
                factors.append(
                    f"URL shortener with {len(feat.redirect_chain) - 1} redirect(s) — final: {feat.final_url[:60] if feat.final_url else '?'}"
                )

            if feat.ml_phishing_score is not None:
                if feat.ml_phishing_score > 0.8:
                    score += 20
                    factors.append(f"ML classifier: high phishing probability ({feat.ml_phishing_score:.0%})")
                elif feat.ml_phishing_score > 0.6:
                    score += 10
                    factors.append(f"ML classifier: moderate phishing probability ({feat.ml_phishing_score:.0%})")

        return score, factors

    @staticmethod
    def _score_keywords(
        kw: KeywordDetectionResult | None,
        score: int,
        factors: list[str],
    ) -> tuple[int, list[str]]:
        if not kw or kw.total_weight == 0:
            return score, factors

        cats = ", ".join(kw.categories) if kw.categories else "unknown"
        if kw.total_weight >= 10:
            score += 15
            factors.append(f"Phishing keywords: high density (weight {kw.total_weight}) — {cats}")
        elif kw.total_weight >= 5:
            score += 8
            factors.append(f"Phishing keywords: moderate density (weight {kw.total_weight}) — {cats}")

        return score, factors

    # ── Thresholds ────────────────────────────────────────────────────────────

    @staticmethod
    def _score_to_level(score: int) -> RiskLevel:
        if score >= 75:
            return RiskLevel.MALICIOUS
        if score >= 25:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.CLEAN
