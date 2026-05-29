from __future__ import annotations

import base64
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.scan import ThreatIntelResult

logger = get_logger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = httpx.Timeout(timeout=20.0)


class VirusTotalClient:
    """
    Async VirusTotal API v3 client.

    Supports URL, domain, and IP address lookups. Each method returns a
    normalized ThreatIntelResult so the risk engine has a uniform interface
    regardless of which artifact type was analyzed.

    Free tier: 4 requests/min, 500/day.
    """

    def __init__(self) -> None:
        self._api_key = get_settings().virustotal_api_key

    @property
    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    def _is_configured(self) -> bool:
        return bool(self._api_key)

    # ── Public lookup methods ─────────────────────────────────────────────────

    async def scan_url(self, url: str) -> ThreatIntelResult:
        """Look up a URL's reputation using its base64url-encoded identifier."""
        if not self._is_configured():
            return self._unconfigured_result("virustotal_url")

        # VT identifies URLs by base64url encoding (no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        endpoint = f"{_VT_BASE}/urls/{url_id}"

        logger.info("virustotal_url_lookup", url=url)
        return await self._get(endpoint, label="virustotal_url")

    async def scan_domain(self, domain: str) -> ThreatIntelResult:
        """Look up a domain's reputation and DNS/WHOIS metadata."""
        if not self._is_configured():
            return self._unconfigured_result("virustotal_domain")

        endpoint = f"{_VT_BASE}/domains/{domain}"
        logger.info("virustotal_domain_lookup", domain=domain)
        return await self._get(endpoint, label="virustotal_domain")

    async def scan_ip(self, ip: str) -> ThreatIntelResult:
        """Look up an IP address's reputation."""
        if not self._is_configured():
            return self._unconfigured_result("virustotal_ip")

        endpoint = f"{_VT_BASE}/ip_addresses/{ip}"
        logger.info("virustotal_ip_lookup", ip=ip)
        return await self._get(endpoint, label="virustotal_ip")

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _get(self, endpoint: str, label: str) -> ThreatIntelResult:
        """Execute a GET request and normalize the VT response."""
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                response = await client.get(endpoint, headers=self._headers)

            if response.status_code == 404:
                # VT has never seen this artifact — not necessarily clean
                return ThreatIntelResult(
                    source=label,
                    detected=False,
                    score=0.0,
                    raw_data={"status": "not_found"},
                )

            if response.status_code == 429:
                logger.warning("virustotal_rate_limited", endpoint=endpoint)
                return ThreatIntelResult(source=label, error="rate_limited")

            response.raise_for_status()
            return self._normalize(label, response.json())

        except httpx.TimeoutException:
            logger.warning("virustotal_timeout", endpoint=endpoint)
            return ThreatIntelResult(source=label, error="timeout")
        except httpx.HTTPStatusError as exc:
            logger.error("virustotal_http_error", status=exc.response.status_code)
            return ThreatIntelResult(source=label, error=f"http_{exc.response.status_code}")
        except Exception as exc:
            logger.error("virustotal_unexpected_error", error=str(exc))
            return ThreatIntelResult(source=label, error="unexpected_error")

    @staticmethod
    def _normalize(label: str, data: dict[str, Any]) -> ThreatIntelResult:
        """
        Convert VT API response into a normalized ThreatIntelResult.

        The key signal is last_analysis_stats.malicious — a non-zero count
        means at least one engine flagged this artifact.
        """
        attrs = data.get("data", {}).get("attributes", {})
        stats: dict[str, int] = attrs.get("last_analysis_stats", {})

        malicious: int = stats.get("malicious", 0)
        suspicious: int = stats.get("suspicious", 0)
        total: int = sum(stats.values()) if stats else 0

        # Normalize: malicious + suspicious detections as a 0–1 confidence score
        score = min((malicious + suspicious) / max(total, 1), 1.0) if total else 0.0
        detected = malicious > 0 or suspicious > 0

        return ThreatIntelResult(
            source=label,
            detected=detected,
            score=round(score, 4),
            raw_data={
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": total,
                "reputation": attrs.get("reputation"),
                "categories": attrs.get("categories"),
            },
        )

    @staticmethod
    def _unconfigured_result(label: str) -> ThreatIntelResult:
        return ThreatIntelResult(source=label, error="api_key_not_configured")
