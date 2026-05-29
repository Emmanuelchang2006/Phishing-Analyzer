from __future__ import annotations

from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.scan import ThreatIntelResult

logger = get_logger(__name__)

_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
_TIMEOUT = httpx.Timeout(timeout=15.0)


class AbuseIPDBClient:
    """
    Async AbuseIPDB v2 client.

    Checks an IP address against AbuseIPDB's crowdsourced threat database.
    Returns a confidence score (0–100) representing how likely the IP is
    to be malicious based on community reports in the last 90 days.

    Free tier: 1,000 checks/day.
    """

    def __init__(self) -> None:
        self._api_key = get_settings().abuseipdb_api_key

    def _is_configured(self) -> bool:
        return bool(self._api_key)

    async def check_ip(self, ip: str, max_age_days: int = 90) -> ThreatIntelResult:
        """
        Check an IP address for abuse reports.

        Args:
            ip:           IPv4 or IPv6 address to check.
            max_age_days: Only include reports from this many days ago. Default 90.
        """
        if not self._is_configured():
            return ThreatIntelResult(source="abuseipdb", error="api_key_not_configured")

        logger.info("abuseipdb_lookup", ip=ip)

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                response = await client.get(
                    f"{_ABUSEIPDB_BASE}/check",
                    params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": False},
                    headers={"Key": self._api_key, "Accept": "application/json"},
                )

            if response.status_code == 429:
                logger.warning("abuseipdb_rate_limited", ip=ip)
                return ThreatIntelResult(source="abuseipdb", error="rate_limited")

            if response.status_code == 422:
                # Unprocessable — likely a private/reserved IP submitted
                return ThreatIntelResult(
                    source="abuseipdb",
                    detected=False,
                    score=0.0,
                    raw_data={"status": "private_or_reserved_ip"},
                )

            response.raise_for_status()
            return self._normalize(response.json())

        except httpx.TimeoutException:
            logger.warning("abuseipdb_timeout", ip=ip)
            return ThreatIntelResult(source="abuseipdb", error="timeout")
        except httpx.HTTPStatusError as exc:
            logger.error("abuseipdb_http_error", status=exc.response.status_code)
            return ThreatIntelResult(source="abuseipdb", error=f"http_{exc.response.status_code}")
        except Exception as exc:
            logger.error("abuseipdb_unexpected_error", error=str(exc))
            return ThreatIntelResult(source="abuseipdb", error="unexpected_error")

    @staticmethod
    def _normalize(data: dict[str, Any]) -> ThreatIntelResult:
        """Convert AbuseIPDB response to a normalized ThreatIntelResult."""
        d = data.get("data", {})

        confidence: int = d.get("abuseConfidenceScore", 0)
        total_reports: int = d.get("totalReports", 0)
        is_tor: bool = d.get("isTor", False)
        usage_type: str | None = d.get("usageType")
        isp: str | None = d.get("isp")
        country: str | None = d.get("countryCode")

        # Score normalized to 0.0–1.0
        score = confidence / 100.0
        detected = confidence >= 25 or is_tor  # 25%+ confidence = flag it

        logger.info(
            "abuseipdb_result",
            confidence=confidence,
            total_reports=total_reports,
            is_tor=is_tor,
        )

        return ThreatIntelResult(
            source="abuseipdb",
            detected=detected,
            score=round(score, 4),
            raw_data={
                "abuse_confidence_score": confidence,
                "total_reports": total_reports,
                "is_tor": is_tor,
                "usage_type": usage_type,
                "isp": isp,
                "country_code": country,
                "last_reported_at": d.get("lastReportedAt"),
            },
        )
