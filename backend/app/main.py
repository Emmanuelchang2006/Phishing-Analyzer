from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.cache.redis_client import close_redis, init_redis
from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging
from app.db.session import close_db, init_db
from app.routers import health, scan

settings = get_settings()

# Bootstrap logging before anything else runs
setup_logging(log_level=settings.log_level, log_format=settings.log_format)
logger = get_logger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application startup / shutdown lifecycle.

    Startup:  Connect to PostgreSQL and Redis. Both are non-fatal —
              the app runs in degraded mode if either is unavailable.
    Shutdown: Gracefully close all connection pools.
    """
    logger.info(
        "application_starting",
        app=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
    )

    db_ok = await init_db()
    redis_ok = await init_redis()

    logger.info(
        "infrastructure_status",
        database=("connected" if db_ok else "unavailable"),
        redis=("connected" if redis_ok else "unavailable"),
    )

    yield  # ← Application runs here

    logger.info("application_shutting_down")
    await close_db()
    await close_redis()


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Production-grade phishing analysis platform. "
            "Combines threat intelligence APIs, email authentication checks, "
            "WHOIS analysis, and AI-powered verdicts to detect phishing attempts."
        ),
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(scan.router)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "unhandled_exception",
            path=str(request.url),
            error=str(exc),
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An unexpected error occurred. Please try again."},
        )

    return app


app = create_app()
