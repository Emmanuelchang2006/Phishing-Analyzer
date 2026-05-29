from __future__ import annotations

import time
from datetime import datetime

from fastapi import APIRouter, status

from app.cache.redis_client import redis_ping
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import get_engine
from app.schemas.health import DependencyStatus, HealthResponse

router = APIRouter(prefix="/api/v1", tags=["Health"])
logger = get_logger(__name__)

_startup_time = time.monotonic()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Application health check",
    description=(
        "Returns operational status and per-dependency health with latency. "
        "Used by load balancers, Kubernetes probes, and uptime monitors."
    ),
)
async def health_check() -> HealthResponse:
    settings = get_settings()
    dependencies: list[DependencyStatus] = []

    # ── PostgreSQL ─────────────────────────────────────────────────────────
    engine = get_engine()
    if engine:
        try:
            import time as _time
            start = _time.monotonic()
            async with engine.connect() as conn:
                await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
            latency_ms = int((_time.monotonic() - start) * 1000)
            dependencies.append(
                DependencyStatus(name="postgresql", status="healthy", latency_ms=latency_ms)
            )
        except Exception as exc:
            dependencies.append(
                DependencyStatus(name="postgresql", status="unhealthy", detail=str(exc))
            )
    else:
        dependencies.append(
            DependencyStatus(
                name="postgresql",
                status="unconfigured",
                detail="Run docker-compose up to start PostgreSQL",
            )
        )

    # ── Redis ──────────────────────────────────────────────────────────────
    redis_reachable, redis_latency = await redis_ping()
    if redis_reachable:
        dependencies.append(
            DependencyStatus(name="redis", status="healthy", latency_ms=redis_latency)
        )
    else:
        from app.cache.redis_client import get_redis
        if get_redis() is None:
            dependencies.append(
                DependencyStatus(
                    name="redis",
                    status="unconfigured",
                    detail="Run docker-compose up to start Redis",
                )
            )
        else:
            dependencies.append(
                DependencyStatus(name="redis", status="unhealthy", detail="Ping failed")
            )

    # ── External APIs ──────────────────────────────────────────────────────
    dependencies.append(
        DependencyStatus(
            name="virustotal",
            status="unconfigured" if not settings.virustotal_api_key else "healthy",
            detail=None if settings.virustotal_api_key else "Set VIRUSTOTAL_API_KEY in .env",
        )
    )
    dependencies.append(
        DependencyStatus(
            name="abuseipdb",
            status="unconfigured" if not settings.abuseipdb_api_key else "healthy",
            detail=None if settings.abuseipdb_api_key else "Set ABUSEIPDB_API_KEY in .env",
        )
    )
    dependencies.append(
        DependencyStatus(
            name="claude_ai",
            status="unconfigured" if not settings.anthropic_api_key else "healthy",
            detail=None if settings.anthropic_api_key else "Set ANTHROPIC_API_KEY in .env",
        )
    )

    # Overall: unhealthy only if a core dep is down; degraded if external APIs missing
    unhealthy = [d for d in dependencies if d.status == "unhealthy"]
    overall_status = "unhealthy" if unhealthy else "healthy"

    logger.info("health_check_requested", status=overall_status)

    return HealthResponse(
        status=overall_status,
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.utcnow(),
        dependencies=dependencies,
        uptime_seconds=round(time.monotonic() - _startup_time, 2),
    )
