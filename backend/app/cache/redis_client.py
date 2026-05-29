from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

import redis.asyncio as aioredis
from redis.asyncio import Redis
from redis.exceptions import ConnectionError as RedisConnectionError, RedisError

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Module-level singleton — initialized in lifespan, None until then
_redis: Optional[Redis] = None


async def init_redis() -> bool:
    """
    Initialize the async Redis connection pool.

    Returns True on success, False if Redis is unreachable (the cache layer
    simply becomes a no-op — scans run uncached).

    Called once from app lifespan on startup.
    """
    global _redis
    settings = get_settings()

    try:
        _redis = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        # Verify the connection is actually usable
        await _redis.ping()
        logger.info("redis_connected", url=settings.redis_url)
        return True

    except (RedisConnectionError, RedisError, OSError) as exc:
        logger.warning(
            "redis_unavailable",
            error=str(exc),
            detail="Results will not be cached until Redis is available",
        )
        _redis = None
        return False


async def close_redis() -> None:
    """Close the Redis connection pool on shutdown."""
    global _redis
    if _redis:
        await _redis.aclose()
        logger.info("redis_disconnected")
        _redis = None


def get_redis() -> Optional[Redis]:
    """Return the Redis client, or None if not initialized."""
    return _redis


# ── Cache helpers ─────────────────────────────────────────────────────────────

def make_scan_cache_key(target: str, scan_type: str) -> str:
    """
    Compute a stable, collision-resistant cache key for a scan.

    SHA-256 of (normalized target + scan_type) keeps the key short and safe
    for Redis, regardless of how long or weird the target URL is.
    """
    payload = f"{target.strip().lower()}:{scan_type}"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f"scan:{digest}"


async def cache_get(key: str) -> dict[str, Any] | None:
    """
    Retrieve a cached JSON value by key.

    Returns None on cache miss, Redis unavailability, or deserialization error.
    Cache errors are always non-fatal.
    """
    if _redis is None:
        return None
    try:
        raw = await _redis.get(key)
        if raw is None:
            return None
        logger.info("cache_hit", key=key)
        return json.loads(raw)
    except (RedisError, json.JSONDecodeError) as exc:
        logger.warning("cache_get_error", key=key, error=str(exc))
        return None


async def cache_set(key: str, value: dict[str, Any], ttl: int | None = None) -> bool:
    """
    Store a JSON-serializable value with an optional TTL (seconds).

    Returns True on success, False on error (non-fatal).
    """
    if _redis is None:
        return False
    try:
        settings = get_settings()
        effective_ttl = ttl if ttl is not None else settings.cache_ttl_seconds
        serialized = json.dumps(value, default=str)  # default=str handles datetime/UUID
        await _redis.setex(key, effective_ttl, serialized)
        logger.info("cache_set", key=key, ttl=effective_ttl)
        return True
    except (RedisError, TypeError) as exc:
        logger.warning("cache_set_error", key=key, error=str(exc))
        return False


async def cache_delete(key: str) -> None:
    """Delete a cached key (used for manual cache invalidation)."""
    if _redis is None:
        return
    try:
        await _redis.delete(key)
    except RedisError as exc:
        logger.warning("cache_delete_error", key=key, error=str(exc))


async def redis_ping() -> tuple[bool, int | None]:
    """
    Health check: ping Redis and return (reachable, latency_ms).
    Used by the /health endpoint.
    """
    if _redis is None:
        return False, None
    import time
    try:
        start = time.monotonic()
        await _redis.ping()
        latency_ms = int((time.monotonic() - start) * 1000)
        return True, latency_ms
    except RedisError:
        return False, None
