from __future__ import annotations

import logging
import sys

import structlog


def setup_logging(log_level: str = "INFO", log_format: str = "console") -> None:
    """
    Configure structlog for the application.

    - "json" format:    Machine-readable JSON lines → suitable for SIEM/log aggregators.
    - "console" format: Human-readable colored output → suitable for local development.

    Called once at application startup in main.py lifespan.
    """

    # Map string level to stdlib constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Configure stdlib logging (uvicorn, sqlalchemy, etc. use stdlib)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
    )

    # Shared processors run on every log event regardless of format.
    # Note: structlog.stdlib.* processors require a stdlib logger backend —
    # use the native structlog equivalents since we're using PrintLoggerFactory.
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,          # Per-request context (request_id, etc.)
        structlog.processors.add_log_level,               # Native equivalent of stdlib.add_log_level
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if log_format == "json":
        # Production: JSON lines for log aggregation pipelines
        processors = shared_processors + [
            structlog.processors.ExceptionRenderer(),
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Development: rich colorized console output
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Return a bound structlog logger for the given module name.

    Usage:
        from app.core.logging import get_logger
        logger = get_logger(__name__)
        logger.info("scan_started", url="https://example.com", request_id="abc123")
    """
    return structlog.get_logger(name)
