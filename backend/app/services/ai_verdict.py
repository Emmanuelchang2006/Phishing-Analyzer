from __future__ import annotations

import json
from typing import TYPE_CHECKING

from google import genai
from google.genai import types

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.verdict import AIVerdict

if TYPE_CHECKING:
    from app.schemas.scan import ScanResponse

logger = get_logger(__name__)

_MODEL = "gemini-2.0-flash"

_SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst specialising in phishing \
detection and threat intelligence. You analyse URLs, domains, IP addresses, and email headers to determine \
whether they represent phishing or other social-engineering threats.

Your analysis must be:
- Evidence-based: cite specific data points from the provided scan results
- Precise: avoid hedging language that reduces actionability
- Calibrated: match confidence to the strength of the available evidence

Verdict classifications:
- phishing    : High confidence the target is used for credential theft, impersonation, or malicious redirection
- suspicious  : Multiple indicators raise concern but evidence is not conclusive
- legitimate  : No significant threat indicators; infrastructure appears benign
- unknown     : Data is insufficient or contradictory; cannot make a reliable determination

Key indicators you should consider:
1. VirusTotal detection ratio (e.g. 15/90 engines flagged = strong signal)
2. AbuseIPDB confidence score and TOR exit-node status
3. Domain age (recently registered < 30 days is high-risk)
4. SPF / DKIM / DMARC failures on email headers
5. From-domain / Reply-To domain mismatch
6. Overall risk score and contributing factors from the risk engine
7. Inconsistencies across multiple data sources

Respond with a JSON object using exactly this schema — no extra keys, no markdown fences:
{
  "verdict": "<phishing|suspicious|legitimate|unknown>",
  "confidence": <float between 0.0 and 1.0>,
  "executive_summary": "<1-2 sentence plain-language summary for a SOC analyst>",
  "key_indicators": ["<specific evidence item>", ...],
  "recommended_action": "<concrete next step, e.g. Block domain at perimeter firewall>"
}"""


class AIVerdictService:
    """
    Generates AI-powered phishing verdicts using Google Gemini (free tier).

    Uses JSON mode to guarantee structured output. Degrades gracefully when
    GEMINI_API_KEY is not configured — returns None so the scan result is
    still fully returned without the AI verdict panel.

    Free tier limits: 15 requests/min, 1 million tokens/day (Gemini 2.0 Flash).
    Get a key at: https://aistudio.google.com/app/apikey
    """

    def __init__(self) -> None:
        if settings.gemini_api_key:
            self._client: genai.Client | None = genai.Client(api_key=settings.gemini_api_key)
        else:
            self._client = None

    async def generate(self, scan_result: ScanResponse) -> AIVerdict | None:
        if self._client is None:
            logger.info("ai_verdict_skipped", reason="GEMINI_API_KEY not configured")
            return None

        user_prompt = _build_user_prompt(scan_result)

        try:
            response = await self._client.aio.models.generate_content(
                model=_MODEL,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=_SYSTEM_PROMPT,
                    response_mime_type="application/json",
                ),
            )
            raw = response.text
        except Exception as exc:
            logger.warning("ai_verdict_gemini_error", error=str(exc))
            return None

        try:
            data: dict = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("ai_verdict_invalid_json", preview=raw[:200] if raw else "")
            return None

        try:
            verdict = AIVerdict(
                verdict=data["verdict"],
                confidence=float(data["confidence"]),
                executive_summary=data["executive_summary"],
                key_indicators=data.get("key_indicators", []),
                recommended_action=data["recommended_action"],
                model=_MODEL,
                cached=False,
            )
        except (KeyError, ValueError) as exc:
            logger.warning("ai_verdict_parse_error", error=str(exc))
            return None

        logger.info(
            "ai_verdict_generated",
            verdict=verdict.verdict,
            confidence=verdict.confidence,
            model=_MODEL,
        )
        return verdict


# ── Private helpers ────────────────────────────────────────────────────────────

def _build_user_prompt(scan: ScanResponse) -> str:
    """Serialise the scan result into a focused analyst brief for Gemini."""
    parts: list[str] = [
        f"**Scan Target:** {scan.target}",
        f"**Type:** {scan.scan_type}",
    ]

    if scan.risk_score:
        parts.append(
            f"**Risk Engine:** score={scan.risk_score.score}/100  "
            f"level={scan.risk_score.level}  "
            f"confidence={scan.risk_score.confidence:.0%}"
        )
        if scan.risk_score.contributing_factors:
            factors = "\n  - ".join(scan.risk_score.contributing_factors)
            parts.append(f"**Risk Factors:**\n  - {factors}")

    if scan.threat_intel:
        lines: list[str] = []
        for ti in scan.threat_intel:
            detected = "DETECTED" if ti.detected else ("clean" if ti.detected is False else "n/a")
            score_str = f"  score={ti.score:.2f}" if ti.score is not None else ""
            err_str = f"  error={ti.error}" if ti.error else ""
            lines.append(f"  - {ti.source}: {detected}{score_str}{err_str}")
        parts.append("**Threat Intel:**\n" + "\n".join(lines))

    if scan.whois:
        w = scan.whois
        age = f"{w.domain_age_days}d" if w.domain_age_days is not None else "unknown"
        parts.append(
            f"**WHOIS:** age={age}  recently_registered={w.recently_registered}  "
            f"registrar={w.registrar or 'unknown'}  country={w.country or 'unknown'}"
        )

    if scan.email_auth:
        ea = scan.email_auth
        parts.append(
            f"**Email Auth:** SPF={ea.spf_status or 'none'}  "
            f"DKIM={ea.dkim_status or 'none'}  "
            f"DMARC={ea.dmarc_status or 'none'}  "
            f"domain_mismatch={ea.domain_mismatch}"
        )

    return "\n".join(parts)
