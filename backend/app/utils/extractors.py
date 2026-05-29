from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class EmailArtifacts:
    """Structured artifacts extracted from raw email headers."""

    from_address: str | None = None
    from_domain: str | None = None
    reply_to_address: str | None = None
    reply_to_domain: str | None = None
    return_path_domain: str | None = None
    received_ips: list[str] = field(default_factory=list)
    message_id: str | None = None
    subject: str | None = None
    auth_results_raw: str | None = None   # Raw Authentication-Results header value

    @property
    def domain_mismatch(self) -> bool:
        """True when From and Reply-To use different domains — a common phishing signal."""
        if self.from_domain and self.reply_to_domain:
            return self.from_domain.lower() != self.reply_to_domain.lower()
        return False


# Matches IPv4 addresses embedded in Received headers ("from [1.2.3.4]")
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_EMAIL_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[a-zA-Z]{2,})")
_HEADER_LINE_RE = re.compile(r"^([\w-]+):\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def extract_domain_from_url(url: str) -> str | None:
    """Return the hostname from a URL, stripping leading www."""
    try:
        host = urlparse(url).hostname or ""
        return re.sub(r"^www\.", "", host) or None
    except Exception:
        return None


def extract_email_artifacts(raw_headers: str) -> EmailArtifacts:
    """
    Parse raw email headers into structured artifacts for threat analysis.

    Handles both full RFC 5322 messages and header-only pastes. Does not
    rely on the stdlib email module so it degrades gracefully on malformed input.
    """
    artifacts = EmailArtifacts()

    # Build a dict of header name → last value (fold multi-line headers)
    headers: dict[str, str] = {}
    for match in _HEADER_LINE_RE.finditer(raw_headers):
        name = match.group(1).lower()
        value = match.group(2).strip()
        headers[name] = value

    # From
    if from_val := headers.get("from"):
        artifacts.from_address = from_val
        m = _EMAIL_RE.search(from_val)
        if m:
            artifacts.from_domain = m.group(1).lower()

    # Reply-To
    if rt := headers.get("reply-to"):
        artifacts.reply_to_address = rt
        m = _EMAIL_RE.search(rt)
        if m:
            artifacts.reply_to_domain = m.group(1).lower()

    # Return-Path
    if rp := headers.get("return-path"):
        m = _EMAIL_RE.search(rp)
        if m:
            artifacts.return_path_domain = m.group(1).lower()

    # Message-ID / Subject
    artifacts.message_id = headers.get("message-id")
    artifacts.subject = headers.get("subject")

    # Authentication-Results (raw — parsed in email_auth service)
    artifacts.auth_results_raw = headers.get("authentication-results")

    # Extract IPs from all Received headers (skip RFC-1918 / loopback)
    import ipaddress
    for line in raw_headers.splitlines():
        if line.lower().startswith("received:"):
            for ip_str in _IPV4_RE.findall(line):
                try:
                    addr = ipaddress.ip_address(ip_str)
                    if not addr.is_private and not addr.is_loopback:
                        if ip_str not in artifacts.received_ips:
                            artifacts.received_ips.append(ip_str)
                except ValueError:
                    continue

    return artifacts
