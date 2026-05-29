from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from app.schemas.verdict import AIVerdict


class ScanType(str, Enum):
    URL = "url"
    EMAIL = "email"
    DOMAIN = "domain"
    IP = "ip"


class RiskLevel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


# ── Request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Payload accepted by POST /api/v1/scan"""

    target: str = Field(
        ...,
        min_length=1,
        max_length=32768,  # Email headers can be several KB; phishing URLs often have long encoded payloads
        description="URL, domain, IP address, or raw email headers to analyze",
        examples=["https://suspicious-login.example.com/verify?token=abc123"],
    )
    scan_type: ScanType = Field(
        default=ScanType.URL,
        description="Type of artifact being scanned",
    )
    options: ScanOptions = Field(
        default_factory=lambda: ScanOptions(),
        description="Optional feature flags to enable specific analysis modules",
    )

    @field_validator("target")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class ScanOptions(BaseModel):
    """Feature flags controlling which analysis modules run."""

    check_virustotal: bool = True
    check_abuseipdb: bool = True
    check_whois: bool = True
    check_email_auth: bool = True   # SPF / DKIM / DMARC
    generate_ai_verdict: bool = True


# ── Response models ───────────────────────────────────────────────────────────

class ThreatIntelResult(BaseModel):
    """Result from a single threat intelligence source."""

    source: str
    detected: bool | None = None
    score: float | None = None          # 0.0 – 1.0 normalized confidence
    raw_data: dict[str, Any] | None = None
    error: str | None = None


class EmailAuthResult(BaseModel):
    """SPF / DKIM / DMARC authentication analysis."""

    spf_status: str | None = None       # pass | fail | softfail | neutral | none
    dkim_status: str | None = None      # pass | fail | none
    dmarc_status: str | None = None     # pass | fail | none
    from_domain: str | None = None
    reply_to_domain: str | None = None
    domain_mismatch: bool = False       # True when From ≠ Reply-To domain


class WhoisResult(BaseModel):
    """WHOIS domain registration data."""

    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    domain_age_days: int | None = None
    country: str | None = None
    recently_registered: bool = False   # True if domain < 30 days old


class RiskScore(BaseModel):
    """Composite risk score aggregated across all analysis modules."""

    score: int = Field(..., ge=0, le=100, description="0 = clean, 100 = definite phishing")
    level: RiskLevel
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the verdict")
    contributing_factors: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons that raised the risk score",
    )


class ScanResponse(BaseModel):
    """Full analysis result returned by POST /api/v1/scan"""

    scan_id: UUID = Field(default_factory=uuid4)
    target: str
    scan_type: ScanType
    status: str = "completed"           # queued | running | completed | failed
    risk_score: RiskScore | None = None
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    email_auth: EmailAuthResult | None = None
    whois: WhoisResult | None = None
    ai_verdict: AIVerdict | None = None  # Structured Claude verdict (Phase 4+)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: int | None = None      # Wall-clock time for the full scan


class ScanStatusResponse(BaseModel):
    """Lightweight status poll response for async scans."""

    scan_id: UUID
    status: str
    progress_pct: int = Field(default=0, ge=0, le=100)
    message: str | None = None
