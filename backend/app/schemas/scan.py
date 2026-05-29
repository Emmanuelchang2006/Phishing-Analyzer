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
        max_length=32768,
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
    check_email_auth: bool = True
    generate_ai_verdict: bool = True
    check_typosquatting: bool = True
    check_url_analysis: bool = True
    check_keywords: bool = True
    generate_mitre_mapping: bool = True


# ── Response models ───────────────────────────────────────────────────────────

class ThreatIntelResult(BaseModel):
    """Result from a single threat intelligence source."""

    source: str
    detected: bool | None = None
    score: float | None = None
    raw_data: dict[str, Any] | None = None
    error: str | None = None


class EmailAuthResult(BaseModel):
    """SPF / DKIM / DMARC authentication analysis."""

    spf_status: str | None = None
    dkim_status: str | None = None
    dmarc_status: str | None = None
    from_domain: str | None = None
    reply_to_domain: str | None = None
    domain_mismatch: bool = False


class WhoisResult(BaseModel):
    """WHOIS domain registration data."""

    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    domain_age_days: int | None = None
    country: str | None = None
    recently_registered: bool = False


class RiskScore(BaseModel):
    """Composite risk score aggregated across all analysis modules."""

    score: int = Field(..., ge=0, le=100, description="0 = clean, 100 = definite phishing")
    level: RiskLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    contributing_factors: list[str] = Field(default_factory=list)


# ── Sprint 2: Typosquatting ───────────────────────────────────────────────────

class TyposquattingMatch(BaseModel):
    """A domain that closely resembles a known brand domain."""

    brand: str
    brand_domain: str
    distance: int
    similarity: float


class TyposquattingResult(BaseModel):
    """Typosquatting detection result."""

    is_typosquatting: bool = False
    matches: list[TyposquattingMatch] = Field(default_factory=list)
    checked_domain: str | None = None


# ── Sprint 2: URL analysis ────────────────────────────────────────────────────

class URLFeatures(BaseModel):
    """Feature analysis of a single URL."""

    url: str
    entropy: float | None = None
    is_shortener: bool = False
    has_credential_keywords: bool = False
    has_homograph: bool = False
    redirect_chain: list[str] = Field(default_factory=list)
    final_url: str | None = None
    ml_phishing_score: float | None = None


class URLAnalysisResult(BaseModel):
    """Analysis of URLs extracted from the scan target."""

    extracted_urls: list[str] = Field(default_factory=list)
    analyzed_urls: list[URLFeatures] = Field(default_factory=list)
    high_risk_urls: list[str] = Field(default_factory=list)


# ── Sprint 2: Keyword detection ───────────────────────────────────────────────

class KeywordMatch(BaseModel):
    """A single phishing keyword match with surrounding context."""

    keyword: str
    category: str
    weight: int
    context: str | None = None


class KeywordDetectionResult(BaseModel):
    """Phishing keyword detection result."""

    matches: list[KeywordMatch] = Field(default_factory=list)
    total_weight: int = 0
    categories: list[str] = Field(default_factory=list)


# ── Sprint 2: MITRE ATT&CK ───────────────────────────────────────────────────

class MITRETactic(BaseModel):
    """A mapped MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str
    reason: str


class MITREResult(BaseModel):
    """MITRE ATT&CK technique mappings for this scan."""

    techniques: list[MITRETactic] = Field(default_factory=list)


# ── Sprint 2: Email header deep analysis ─────────────────────────────────────

class ReceivedHop(BaseModel):
    """Single hop parsed from an email Received header."""

    raw: str
    from_host: str | None = None
    by_host: str | None = None
    ip: str | None = None
    timestamp: str | None = None


class EmailHeadersAnalysis(BaseModel):
    """Deep structural analysis of email routing headers."""

    hop_count: int = 0
    hops: list[ReceivedHop] = Field(default_factory=list)
    originating_ip: str | None = None
    x_mailer: str | None = None
    suspicious_mailer: bool = False


# ── Full scan response ────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """Full analysis result returned by POST /api/v1/scan"""

    scan_id: UUID = Field(default_factory=uuid4)
    target: str
    scan_type: ScanType
    status: str = "completed"
    risk_score: RiskScore | None = None
    threat_intel: list[ThreatIntelResult] = Field(default_factory=list)
    email_auth: EmailAuthResult | None = None
    whois: WhoisResult | None = None
    ai_verdict: AIVerdict | None = None
    typosquatting: TyposquattingResult | None = None
    url_analysis: URLAnalysisResult | None = None
    keywords: KeywordDetectionResult | None = None
    mitre_tactics: MITREResult | None = None
    email_headers: EmailHeadersAnalysis | None = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: int | None = None


class ScanStatusResponse(BaseModel):
    """Lightweight status poll response for async scans."""

    scan_id: UUID
    status: str
    progress_pct: int = Field(default=0, ge=0, le=100)
    message: str | None = None
