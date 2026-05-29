from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class DependencyStatus(BaseModel):
    """Status of a single external dependency."""

    name: str
    status: str          # healthy | degraded | unhealthy | unconfigured
    latency_ms: int | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    """
    Response for GET /api/v1/health

    Returns overall app status and per-dependency health. Monitoring systems
    (Kubernetes probes, uptime checks) key off the top-level `status` field.
    """

    status: str          # healthy | degraded | unhealthy
    app_name: str
    version: str
    environment: str
    timestamp: datetime = datetime.utcnow()
    dependencies: list[DependencyStatus] = []
    uptime_seconds: float | None = None
