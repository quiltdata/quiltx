"""Catalog DNS identity helpers."""

from __future__ import annotations

import re
from urllib.parse import urlparse


def normalize_dns(value: str) -> str:
    """Normalize a catalog identifier to a bare DNS name.

    Accepts a plain DNS name or an https:// URL and returns the lowercase
    hostname with no scheme, path, query, or trailing slash.

    Args:
        value: DNS name or https:// URL for a Quilt catalog.

    Returns:
        Lowercase hostname, e.g. ``"customer-acme.quilt.example"``.

    Raises:
        ValueError: For http://, custom ports, IP literals, or empty input.
    """
    value = value.strip()
    if not value:
        raise ValueError("catalog DNS name is required")

    # Reject http:// explicitly before urlparse interprets it
    if value.lower().startswith("http://"):
        raise ValueError(
            "http:// is not supported. Use https:// or pass the DNS name directly."
        )

    # Strip https:// if present so urlparse can give us a clean netloc
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() != "https":
            raise ValueError(
                "http:// is not supported. Use https:// or pass the DNS name directly."
            )
        host = parsed.hostname or ""
        port = parsed.port
    else:
        # Plain hostname — no scheme; urlparse won't split netloc correctly
        # so extract the host manually before any colon
        host_part = value.split("/")[0]  # strip any accidental path
        if ":" in host_part:
            host = host_part.split(":")[0]
            port = int(host_part.split(":")[1]) if host_part.split(":")[1] else None
        else:
            host = host_part
            port = None

    host = host.lower()

    if not host:
        raise ValueError("catalog DNS name is required")

    # Reject custom ports
    if port is not None:
        raise ValueError("Custom ports are not supported. Use the bare DNS name.")

    # Reject IP literals (IPv4 and IPv6)
    if _is_ip_address(host):
        raise ValueError("IP-address identifiers are not supported. Use the DNS name.")

    return host


def _is_ip_address(host: str) -> bool:
    """Return True if host looks like an IPv4 or IPv6 address."""
    # IPv4: four dot-separated decimal octets
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return True
    # IPv6: contains colons (already stripped of brackets by urlparse)
    if ":" in host:
        return True
    return False
