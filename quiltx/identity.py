"""Catalog DNS identity helpers."""

from __future__ import annotations

from quiltx.auth import _native

LOCALHOST = "localhost"


def is_localhost(dns: str) -> bool:
    """True if *dns* identifies the local machine for --insecure testing."""
    return dns.strip().lower() == LOCALHOST


def build_catalog_url(dns: str, *, insecure: bool = False) -> str:
    """Build the canonical https:// (or http:// for insecure localhost) URL."""
    if insecure and is_localhost(dns):
        return f"http://{dns}"
    return f"https://{dns}"


def normalize_dns(value: str, *, insecure: bool = False) -> str:
    """Normalize a catalog identifier to a bare DNS name.

    Accepts a plain DNS name or an https:// URL and returns the lowercase
    hostname with no scheme, path, query, or trailing slash. The work is done
    in Rust (``quiltx._core``); the behaviour, including every error message,
    is that of the Python implementation it replaced (``tests/oracle.py``).

    Args:
        value: DNS name or https:// URL for a Quilt catalog.
        insecure: When True, also accept ``http://localhost`` for local
            catalog testing. Any other use of http:// or any non-localhost
            target with insecure=True is still rejected.

    Returns:
        Lowercase hostname, e.g. ``"customer-acme.quilt.example"``.

    Raises:
        ValueError: For http://, custom ports, IP literals, or empty input.
            (insecure=True relaxes only the http://localhost case.)
    """
    return _native.normalize_dns(value, bool(insecure))
