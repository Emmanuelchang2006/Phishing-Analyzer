from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from functools import partial
from typing import Any

import whois

from app.core.logging import get_logger
from app.schemas.scan import WhoisResult

logger = get_logger(__name__)

# Domains registered within this many days are flagged as recently registered
_RECENT_REGISTRATION_DAYS = 30


class WhoisService:
    """
    WHOIS domain registration lookup service.

    python-whois is a synchronous library, so we run it in a thread pool
    executor to keep the async event loop unblocked.

    Key signals extracted:
      - domain_age_days:       Very young domains (< 30 days) are high-risk
      - recently_registered:   Boolean flag for the risk engine
      - registrar:             Bulk/privacy registrars correlate with abuse
      - expiration_date:       Domains expiring soon may be abandoned / squatted
    """

    async def lookup(self, domain: str) -> WhoisResult:
        """
        Perform an async WHOIS lookup for the given domain.

        Runs the blocking python-whois call in a thread pool so it doesn't
        stall the event loop while waiting on the WHOIS server response.
        """
        logger.info("whois_lookup", domain=domain)

        try:
            loop = asyncio.get_event_loop()
            # Run the blocking call off the event loop thread
            raw = await loop.run_in_executor(None, partial(whois.whois, domain))
            return self._normalize(raw)

        except Exception as exc:
            logger.warning("whois_lookup_failed", domain=domain, error=str(exc))
            # WHOIS failure is non-fatal — return a partial result
            return WhoisResult()

    @staticmethod
    def _normalize(raw: Any) -> WhoisResult:
        """Extract the signals we care about from the raw whois object."""

        def _first_date(value: Any) -> datetime | None:
            """Handle both single datetime and list[datetime] from python-whois."""
            if isinstance(value, list):
                value = value[0] if value else None
            if isinstance(value, datetime):
                # Normalize to UTC-aware
                if value.tzinfo is None:
                    return value.replace(tzinfo=timezone.utc)
                return value
            return None

        creation = _first_date(getattr(raw, "creation_date", None))
        expiration = _first_date(getattr(raw, "expiration_date", None))

        # Calculate domain age
        domain_age_days: int | None = None
        if creation:
            now = datetime.now(timezone.utc)
            domain_age_days = max(0, (now - creation).days)

        recently_registered = (
            domain_age_days is not None and domain_age_days < _RECENT_REGISTRATION_DAYS
        )

        registrar = getattr(raw, "registrar", None)
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        country = getattr(raw, "country", None)
        if isinstance(country, list):
            country = country[0] if country else None

        logger.info(
            "whois_result",
            domain_age_days=domain_age_days,
            recently_registered=recently_registered,
            registrar=registrar,
        )

        return WhoisResult(
            registrar=registrar,
            creation_date=creation,
            expiration_date=expiration,
            domain_age_days=domain_age_days,
            country=country,
            recently_registered=recently_registered,
        )
