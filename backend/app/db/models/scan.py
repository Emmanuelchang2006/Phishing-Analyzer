from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanRecord(Base):
    """
    Persisted record of a completed phishing scan.

    Scalar columns are indexed for dashboard queries:
      - target:      full-text search for "show all scans of this URL"
      - risk_level:  filter "show all malicious scans today"
      - created_at:  time-range queries for the dashboard timeline

    result_json stores the complete ScanResponse as JSONB. This lets Phase 5
    reconstruct the full frontend card from the DB without a JOIN, and lets
    Phase 4 (Claude) re-read full context when generating verdicts.
    """

    __tablename__ = "scans"

    # Primary key — same UUID that was returned to the caller in ScanResponse
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # ── Target metadata ───────────────────────────────────────────────────────
    target: Mapped[str] = mapped_column(Text, nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # SHA-256 of (target + scan_type) — used as cache key lookup

    # ── Result summary (scalar, indexed for fast filtering) ───────────────────
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Full result (JSONB — flexible, no migration needed for result schema changes)
    result_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    # Composite index: most dashboard queries filter by (risk_level, created_at)
    __table_args__ = (
        Index("ix_scans_risk_level_created_at", "risk_level", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<ScanRecord id={self.id} target={self.target!r} level={self.risk_level}>"
