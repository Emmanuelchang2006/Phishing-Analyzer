from __future__ import annotations

import asyncio
import time
from typing import Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from app.cache.redis_client import cache_get, cache_set, make_scan_cache_key
from app.core.logging import get_logger
from app.repositories.scan_repository import ScanRepository
from app.schemas.scan import (
    EmailAuthResult,
    ScanRequest,
    ScanResponse,
    ScanType,
    ThreatIntelResult,
    WhoisResult,
)
from app.services.abuseipdb import AbuseIPDBClient
from app.services.ai_verdict import AIVerdictService
from app.services.email_auth import EmailAuthService
from app.services.risk_engine import RiskContext, RiskEngine
from app.services.virustotal import VirusTotalClient
from app.services.whois_service import WhoisService
from app.utils.extractors import extract_email_artifacts
from app.utils.validators import classify_target, extract_domain_from_url

logger = get_logger(__name__)


class ScanService:
    """
    Orchestrates the full phishing analysis pipeline with caching and persistence.

    Request flow:
      1. Compute cache key from (target, scan_type)
      2. Redis cache hit?  → Return cached ScanResponse immediately
      3. DB recent hit?    → Return stored ScanResponse (fallback if Redis cold)
      4. Cache miss        → Run full concurrent analysis pipeline
      5. Persist result    → Write to PostgreSQL (non-fatal if DB unavailable)
      6. Cache result      → Write to Redis (non-fatal if Redis unavailable)
      7. Return ScanResponse

    DB and Redis failures are non-fatal — the scan result is still returned.
    """

    def __init__(self) -> None:
        self._vt = VirusTotalClient()
        self._abuseipdb = AbuseIPDBClient()
        self._whois = WhoisService()
        self._email_auth = EmailAuthService()
        self._risk_engine = RiskEngine()
        self._ai_verdict = AIVerdictService()

    async def run_scan(
        self,
        request: ScanRequest,
        db: Optional[AsyncSession] = None,
    ) -> ScanResponse:
        scan_type = classify_target(request.target, request.scan_type)
        cache_key = make_scan_cache_key(request.target, scan_type.value)

        # ── Step 1: Cache-aside lookup ────────────────────────────────────────
        cached = await cache_get(cache_key)
        if cached:
            logger.info("scan_cache_hit", target=request.target, scan_type=scan_type)
            return ScanResponse(**cached)

        # ── Step 2: DB deduplication (if Redis was cold/empty) ────────────────
        if db is not None:
            repo = ScanRepository(db)
            existing = await repo.get_recent_by_hash(
                cache_key,
                max_age_seconds=3600,
            )
            if existing and existing.result_json:
                logger.info("scan_db_dedup_hit", scan_id=str(existing.id))
                result = ScanResponse(**existing.result_json)
                # Warm the cache so the next hit is faster
                await cache_set(cache_key, existing.result_json)
                return result

        # ── Step 3: Run full pipeline ─────────────────────────────────────────
        scan_id = uuid4()
        start = time.monotonic()

        logger.info(
            "scan_started",
            scan_id=str(scan_id),
            target=request.target,
            scan_type=scan_type,
        )

        threat_intel, whois_result, email_auth_result = await self._dispatch(
            request.target, scan_type, request.options
        )

        risk_score = self._risk_engine.compute(
            RiskContext(
                threat_intel=threat_intel,
                whois=whois_result,
                email_auth=email_auth_result,
            )
        )

        # ── Step 3b: AI verdict (non-fatal if Claude is unavailable) ─────────
        ai_verdict = None
        if request.options.generate_ai_verdict:
            try:
                _partial = ScanResponse(
                    scan_id=scan_id,
                    target=request.target,
                    scan_type=scan_type,
                    risk_score=risk_score,
                    threat_intel=threat_intel,
                    whois=whois_result,
                    email_auth=email_auth_result,
                )
                ai_verdict = await self._ai_verdict.generate(_partial)
            except Exception as exc:
                logger.warning("ai_verdict_scan_error", error=str(exc))

        duration_ms = int((time.monotonic() - start) * 1000)

        response = ScanResponse(
            scan_id=scan_id,
            target=request.target,
            scan_type=scan_type,
            status="completed",
            risk_score=risk_score,
            threat_intel=threat_intel,
            whois=whois_result,
            email_auth=email_auth_result,
            ai_verdict=ai_verdict,
            duration_ms=duration_ms,
        )

        logger.info(
            "scan_completed",
            scan_id=str(scan_id),
            risk_level=risk_score.level,
            risk_score=risk_score.score,
            duration_ms=duration_ms,
        )

        # ── Step 4: Persist to DB (non-fatal) ─────────────────────────────────
        if db is not None:
            await self._persist(response, cache_key, db)

        # ── Step 5: Cache result (non-fatal) ──────────────────────────────────
        await cache_set(cache_key, response.model_dump(mode="json"))

        return response

    # ── Persistence helper ────────────────────────────────────────────────────

    @staticmethod
    async def _persist(
        response: ScanResponse,
        target_hash: str,
        db: AsyncSession,
    ) -> None:
        try:
            repo = ScanRepository(db)
            await repo.save(response, target_hash)
        except Exception as exc:
            logger.warning("scan_persist_failed", error=str(exc))

    # ── Dispatch logic (unchanged from Phase 2) ───────────────────────────────

    async def _dispatch(
        self,
        target: str,
        scan_type: ScanType,
        options,
    ) -> tuple[list[ThreatIntelResult], WhoisResult | None, EmailAuthResult | None]:
        if scan_type == ScanType.URL:
            return await self._scan_url(target, options)
        elif scan_type == ScanType.DOMAIN:
            return await self._scan_domain(target, options)
        elif scan_type == ScanType.IP:
            return await self._scan_ip(target, options)
        elif scan_type == ScanType.EMAIL:
            return await self._scan_email(target, options)
        else:
            return [], None, None

    async def _scan_url(self, url: str, options) -> tuple[list[ThreatIntelResult], WhoisResult | None, EmailAuthResult | None]:
        domain = extract_domain_from_url(url)
        tasks: list = [self._vt.scan_url(url)] if options.check_virustotal else []
        if domain and options.check_virustotal:
            tasks.append(self._vt.scan_domain(domain))

        whois_task = self._whois.lookup(domain) if domain and options.check_whois else None
        auth_task = self._email_auth.check_domain(domain) if domain and options.check_email_auth else None

        gathered = await asyncio.gather(
            *tasks,
            whois_task if whois_task else _noop(),
            auth_task if auth_task else _noop(),
            return_exceptions=True,
        )

        ti_results = [r for r in gathered[: len(tasks)] if isinstance(r, ThreatIntelResult)]
        whois_result = gathered[len(tasks)]
        auth_result = gathered[len(tasks) + 1]

        return (
            ti_results,
            whois_result if isinstance(whois_result, WhoisResult) else None,
            auth_result if isinstance(auth_result, EmailAuthResult) else None,
        )

    async def _scan_domain(self, domain: str, options) -> tuple[list[ThreatIntelResult], WhoisResult | None, EmailAuthResult | None]:
        vt_task = self._vt.scan_domain(domain) if options.check_virustotal else _noop()
        whois_task = self._whois.lookup(domain) if options.check_whois else _noop()
        auth_task = self._email_auth.check_domain(domain) if options.check_email_auth else _noop()

        vt_result, whois_result, auth_result = await asyncio.gather(
            vt_task, whois_task, auth_task, return_exceptions=True
        )

        return (
            [vt_result] if isinstance(vt_result, ThreatIntelResult) else [],
            whois_result if isinstance(whois_result, WhoisResult) else None,
            auth_result if isinstance(auth_result, EmailAuthResult) else None,
        )

    async def _scan_ip(self, ip: str, options) -> tuple[list[ThreatIntelResult], WhoisResult | None, EmailAuthResult | None]:
        vt_task = self._vt.scan_ip(ip) if options.check_virustotal else _noop()
        abuse_task = self._abuseipdb.check_ip(ip) if options.check_abuseipdb else _noop()

        vt_result, abuse_result = await asyncio.gather(vt_task, abuse_task, return_exceptions=True)
        ti_results = [r for r in [vt_result, abuse_result] if isinstance(r, ThreatIntelResult)]
        return ti_results, None, None

    async def _scan_email(self, raw_headers: str, options) -> tuple[list[ThreatIntelResult], WhoisResult | None, EmailAuthResult | None]:
        artifacts = extract_email_artifacts(raw_headers)
        tasks = []

        if options.check_abuseipdb:
            for ip in artifacts.received_ips[:3]:
                tasks.append(self._abuseipdb.check_ip(ip))

        if artifacts.from_domain and options.check_virustotal:
            tasks.append(self._vt.scan_domain(artifacts.from_domain))

        auth_task = self._email_auth.check_email_headers(artifacts) if options.check_email_auth else _noop()
        whois_task = self._whois.lookup(artifacts.from_domain) if artifacts.from_domain and options.check_whois else _noop()

        results = await asyncio.gather(*tasks, auth_task, whois_task, return_exceptions=True)

        ti_results = [r for r in results[: len(tasks)] if isinstance(r, ThreatIntelResult)]
        auth_result = results[len(tasks)]
        whois_result = results[len(tasks) + 1]

        return (
            ti_results,
            whois_result if isinstance(whois_result, WhoisResult) else None,
            auth_result if isinstance(auth_result, EmailAuthResult) else None,
        )


async def _noop() -> None:
    return None
