from __future__ import annotations

import asyncio
import re
from functools import partial

import dns.resolver
import dns.exception

from app.core.logging import get_logger
from app.schemas.scan import EmailAuthResult
from app.utils.extractors import EmailArtifacts

logger = get_logger(__name__)

_DNS_TIMEOUT = 5.0  # seconds per DNS query


async def _async_none() -> None:
    """Placeholder coroutine for optional async tasks."""
    return None


class EmailAuthService:
    """
    SPF / DKIM / DMARC DNS authentication checker.

    Can operate in two modes:
      1. Domain-only:   Checks SPF + DMARC for a domain extracted from a URL.
      2. Email headers: Parses artifacts from raw headers then checks all three
                        protocols plus domain mismatch signals.

    DNS queries run in a thread pool (dnspython is synchronous) to avoid
    blocking the event loop.
    """

    async def check_domain(self, domain: str) -> EmailAuthResult:
        """
        Run SPF and DMARC checks for a bare domain.

        Used when the scan target is a URL or domain (not raw email headers).
        DKIM requires an email-specific selector so it's skipped here.
        """
        logger.info("email_auth_domain_check", domain=domain)

        spf_status, dmarc_status = await asyncio.gather(
            self._check_spf(domain),
            self._check_dmarc(domain),
        )

        return EmailAuthResult(
            spf_status=spf_status,
            dmarc_status=dmarc_status,
            from_domain=domain,
        )

    async def check_email_headers(self, artifacts: EmailArtifacts) -> EmailAuthResult:
        """
        Run full SPF / DKIM / DMARC checks using parsed email artifacts.

        DKIM is checked when we can find a selector in the Authentication-Results
        header. Falls back gracefully when the selector is unavailable.
        """
        domain = artifacts.from_domain
        if not domain:
            logger.warning("email_auth_no_from_domain")
            return EmailAuthResult()

        logger.info("email_auth_headers_check", domain=domain)

        # Extract DKIM selector from Authentication-Results if present
        dkim_selector = self._extract_dkim_selector(artifacts.auth_results_raw)

        # Build task list — DKIM only runs when we have a selector
        dkim_coro = (
            self._check_dkim(domain, dkim_selector) if dkim_selector else _async_none()
        )

        spf_status, dmarc_status, dkim_raw = await asyncio.gather(
            self._check_spf(domain),
            self._check_dmarc(domain),
            dkim_coro,
        )

        # The Authentication-Results header (set by the receiving MTA) is more
        # authoritative than our DNS checks — prefer it when available.
        ar_spf, ar_dkim, ar_dmarc = self._parse_auth_results_header(
            artifacts.auth_results_raw
        )

        return EmailAuthResult(
            spf_status=ar_spf or spf_status,
            dkim_status=ar_dkim or dkim_raw,
            dmarc_status=ar_dmarc or dmarc_status,
            from_domain=artifacts.from_domain,
            reply_to_domain=artifacts.reply_to_domain,
            domain_mismatch=artifacts.domain_mismatch,
        )

    # ── DNS lookup helpers ────────────────────────────────────────────────────

    async def _check_spf(self, domain: str) -> str:
        """
        Look up TXT records for the domain and find the SPF record.

        Returns: "pass" (record exists), "none" (no record), or "error".
        Note: A full SPF *evaluation* requires the sending IP — here we check
        record existence and policy directive as a baseline signal.
        """
        records = await self._dns_txt_lookup(domain)
        for record in records:
            if record.lower().startswith("v=spf1"):
                if "-all" in record:
                    return "pass"       # Strict policy
                elif "~all" in record:
                    return "softfail"
                elif "?all" in record:
                    return "neutral"
                return "pass"           # SPF exists, permissive
        return "none"

    async def _check_dmarc(self, domain: str) -> str:
        """
        Look up the DMARC policy at _dmarc.{domain}.

        Returns: "pass" (policy configured), "none" (no record), or "error".
        """
        records = await self._dns_txt_lookup(f"_dmarc.{domain}")
        for record in records:
            if record.lower().startswith("v=dmarc1"):
                match = re.search(r"p=(none|quarantine|reject)", record, re.IGNORECASE)
                if match:
                    policy = match.group(1).lower()
                    if policy in ("quarantine", "reject"):
                        return "pass"   # Enforced policy
                    return "none"       # p=none — monitoring only
                return "pass"
        return "none"

    async def _check_dkim(self, domain: str, selector: str) -> str:
        """Look up the DKIM public key at {selector}._domainkey.{domain}."""
        records = await self._dns_txt_lookup(f"{selector}._domainkey.{domain}")
        for record in records:
            if "v=dkim1" in record.lower() or "p=" in record.lower():
                return "pass"
        return "none"

    async def _dns_txt_lookup(self, name: str) -> list[str]:
        """Run a DNS TXT lookup in a thread pool, returning all record strings."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = _DNS_TIMEOUT
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, partial(resolver.resolve, name, "TXT")
            )
            return [rdata.to_text().strip('"') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            logger.warning("dns_timeout", name=name)
            return []
        except Exception as exc:
            logger.warning("dns_error", name=name, error=str(exc))
            return []

    # ── Header parsing helpers ────────────────────────────────────────────────

    @staticmethod
    def _extract_dkim_selector(auth_results: str | None) -> str | None:
        """Extract DKIM selector from an Authentication-Results header value."""
        if not auth_results:
            return None
        match = re.search(r"header\.s=([\w.-]+)", auth_results, re.IGNORECASE)
        return match.group(1) if match else None

    @staticmethod
    def _parse_auth_results_header(
        auth_results: str | None,
    ) -> tuple[str | None, str | None, str | None]:
        """
        Parse the Authentication-Results header to extract reported SPF/DKIM/DMARC status.

        Returns (spf_status, dkim_status, dmarc_status).
        The receiving MTA reports these — more authoritative than our DNS checks alone.
        """
        if not auth_results:
            return None, None, None

        def _extract(protocol: str) -> str | None:
            pattern = rf"{protocol}\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)"
            match = re.search(pattern, auth_results, re.IGNORECASE)
            return match.group(1).lower() if match else None

        return _extract("spf"), _extract("dkim"), _extract("dmarc")
