from __future__ import annotations

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.session import get_db_session
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import ScanRequest, ScanResponse, ScanStatusResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1", tags=["Scan"])
logger = get_logger(__name__)


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit an artifact for phishing analysis",
    description=(
        "Analyzes a URL, domain, IP address, or email headers for phishing indicators. "
        "Results are cached in Redis and persisted to PostgreSQL. "
        "Duplicate submissions of the same target within the cache TTL return instantly."
    ),
)
async def submit_scan(
    request: Request,
    payload: ScanRequest,
    db: Optional[AsyncSession] = Depends(get_db_session),
) -> ScanResponse:
    """
    Submit an artifact for full phishing analysis.

    Checks Redis and PostgreSQL for a recent cached result before running
    the full pipeline. Cache TTL is controlled by CACHE_TTL_SECONDS (.env).
    """
    logger.info(
        "scan_request_received",
        target=payload.target,
        scan_type=payload.scan_type,
        client_ip=request.client.host if request.client else "unknown",
    )

    service = ScanService()
    result = await service.run_scan(payload, db=db)
    return result


@router.get(
    "/scan/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve a scan result by ID",
    description=(
        "Returns the full result of a previously completed scan. "
        "Checks Redis first, then PostgreSQL. Returns 404 if the scan ID is unknown."
    ),
)
async def get_scan(
    scan_id: UUID,
    db: Optional[AsyncSession] = Depends(get_db_session),
) -> ScanResponse:
    """
    Fetch a completed scan by its UUID.

    Redis → PostgreSQL → 404.
    """
    logger.info("scan_fetch_requested", scan_id=str(scan_id))

    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not available — scan history is offline.",
        )

    repo = ScanRepository(db)
    record = await repo.get_by_id(scan_id)

    if record is None or record.result_json is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found.",
        )

    return ScanResponse(**record.result_json)


@router.get(
    "/scans",
    response_model=list[ScanResponse],
    status_code=status.HTTP_200_OK,
    summary="List recent scans",
    description="Returns the most recent scans, optionally filtered by risk level.",
)
async def list_scans(
    limit: int = 20,
    risk_level: Optional[str] = None,
    db: Optional[AsyncSession] = Depends(get_db_session),
) -> list[ScanResponse]:
    """
    Fetch recent scans for the dashboard.
    Used by Phase 5 frontend to populate the scan history table.
    """
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not available — scan history is offline.",
        )

    repo = ScanRepository(db)
    records = await repo.get_recent_scans(limit=min(limit, 100), risk_level=risk_level)

    return [
        ScanResponse(**r.result_json)
        for r in records
        if r.result_json is not None
    ]
