"""The pre-Rust Python implementations, kept verbatim as the parity oracle.

``quiltx.identity.normalize_dns`` and the credential-path lookups in
``quiltx.auth.store`` now call ``quiltx._core``. These are the functions they
replaced, copied unchanged from quiltx 0.23.1 (commit 70dfd36 of the PR that
introduced ``_core``), so ``tests/test_core_parity.py`` can run old and new on
the same inputs. Nothing under ``quiltx/`` imports this module.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from platformdirs import user_data_path

LOCALHOST = "localhost"


def is_localhost(dns: str) -> bool:
    """True if *dns* identifies the local machine for --insecure testing."""
    return dns.strip().lower() == LOCALHOST


def normalize_dns(value: str, *, insecure: bool = False) -> str:
    """Normalize a catalog identifier to a bare DNS name.

    Accepts a plain DNS name or an https:// URL and returns the lowercase
    hostname with no scheme, path, query, or trailing slash.

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
    value = value.strip()
    if not value:
        raise ValueError("catalog DNS name is required")

    # Reject http:// explicitly before urlparse interprets it.
    # Exception: --insecure permits http://localhost (and bare localhost) for
    # local catalog testing; that branch is taken below after host extraction.
    lowered = value.lower()
    http_prefix = lowered.startswith("http://")
    if http_prefix and not insecure:
        raise ValueError(
            "http:// is not supported. Use https:// or pass the DNS name directly."
        )

    # Strip https:// if present so urlparse can give us a clean netloc
    if "://" in value:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "http"}:
            raise ValueError(
                "http:// is not supported. Use https:// or pass the DNS name directly."
            )
        host = parsed.hostname or ""
        port = parsed.port
        if scheme == "http" and not (insecure and is_localhost(host)):
            raise ValueError("http:// is only supported with --insecure for localhost.")
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

    # --insecure is a localhost-only escape hatch.
    if insecure and not is_localhost(host):
        raise ValueError(
            "--insecure is only supported for localhost; "
            f"refusing to use insecure transport for {host}."
        )

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


def fallback_path() -> Path:
    return user_data_path("quiltx") / "credentials.json"


def index_path() -> Path:
    return user_data_path("quiltx") / "credentials_index.json"


KEYRING_SERVICE = "quiltx"


def keyring_entry(dns: str) -> tuple[str, str]:
    """What ``keyring.get_password(...)`` was called with."""
    return (KEYRING_SERVICE, dns)
