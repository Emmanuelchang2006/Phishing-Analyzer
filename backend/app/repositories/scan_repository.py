from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.models.scan import ScanRecord
from app.schemas.scan import ScanResponse

logger = get_logger(__name__)


class ScanRepository:
    """
    Data access layer for scan records.

    All database interaction for scans goes through this class.
    The constructor takes an AsyncSession so callers (services, routes)
    control transaction scope — the repository never commits on its own.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, response: ScanResponse, target_hash: str) -> ScanRecord:
        """
        Persist a completed ScanResponse to the database.

        Converts the Pydantic model to a ScanRecord ORM object. The full
        response is stored as JSONB so it can be reconstructed exactly.
        """
        record = ScanRecord(
            id=response.scan_id,
            target=response.target,
            scan_type=response.scan_type.value,
            target_hash=target_hash,
            status=response.status,
            risk_score=response.risk_score.score if response.risk_score else None,
            risk_level=response.risk_score.level.value if response.risk_score else None,
            duration_ms=response.duration_ms,
            result_json=response.model_dump(mode="json"),
        )
        self._session.add(record)
        await self._session.flush()  # Send INSERT, let caller decide on commit

        logger.info(
            "scan_persisted",
            scan_id=str(record.id),
            risk_level=record.risk_level,
        )
        return record

    async def get_by_id(self, scan_id: UUID) -> Optional[ScanRecord]:
        """Retrieve a scan record by its UUID primary key."""
        stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_recent_by_hash(
        self,
        target_hash: str,
        max_age_seconds: int = 3600,
    ) -> Optional[ScanRecord]:
        """
        Find a recent scan for the same target (used for deduplication).

        Returns the most recent matching record if it was created within
        max_age_seconds, otherwise None (caller will run a fresh scan).
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)

        stmt = (
            select(ScanRecord)
            .where(
                ScanRecord.target_hash == target_hash,
                ScanRecord.status == "completed",
                ScanRecord.created_at >= cutoff,
            )
            .order_by(ScanRecord.created_at.desc())
            .limit(1)
        )

        result = await self._session.execute(stmt)
        record = result.scalar_one_or_none()

        if record:
            logger.info(
                "dedup_hit",
                target_hash=target_hash,
                scan_id=str(record.id),
                age_seconds=int(
                    (datetime.now(timezone.utc) - record.created_at).total_seconds()
                ),
            )
        return record

    async def get_recent_scans(
        self,
        limit: int = 20,
        risk_level: Optional[str] = None,
    ) -> list[ScanRecord]:
        """
        Fetch recent scans for the dashboard, optionally filtered by risk level.
        """
        stmt = select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)

        if risk_level:
            stmt = stmt.where(ScanRecord.risk_level == risk_level)

        result = await self._session.execute(stmt)
        return list(result.scalars().all())
