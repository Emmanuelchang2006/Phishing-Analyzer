from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.schemas.scan import ScanType

# Matches a bare domain like "evil-login.paypal.com" or "sub.domain.co.uk"
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def classify_target(target: str, declared_type: ScanType) -> ScanType:
    """
    Verify and refine the user-declared scan type against the actual input.

    The user may declare scan_type="url" but submit a bare domain — we
    correct silently so downstream services receive the right type rather
    than crashing on a malformed URL parse.
    """
    t = target.strip()

    # If it looks like an IP address, override whatever was declared.
    if is_ip_address(t):
        return ScanType.IP

    # If it has an http/https scheme it's a URL regardless of declaration.
    if t.startswith(("http://", "https://")):
        return ScanType.URL

    # Email headers contain newlines or "From:" / "Received:" markers.
    if "\n" in t or t.lower().startswith(("from:", "received:", "authentication-results:")):
        return ScanType.EMAIL

    # A bare label without scheme but with a valid TLD → domain
    if is_domain(t):
        return ScanType.DOMAIN

    # Fall back to the user's declared type
    return declared_type


def is_ip_address(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    """Return True if value looks like a bare domain (no scheme, no path)."""
    return bool(_DOMAIN_RE.match(value))


def is_private_ip(value: str) -> bool:
    """Return True if the IP is RFC-1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def extract_domain_from_url(url: str) -> str | None:
    """Extract the hostname from a full URL, stripping www. prefix."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.lstrip("www.") if host else None
    except Exception:
        return None
