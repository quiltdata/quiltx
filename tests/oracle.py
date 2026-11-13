"""The pre-Rust Python implementations, kept verbatim as the parity oracle.

``quiltx.identity.normalize_dns`` and the credential-path, file-store, and
keyring-store lookups in ``quiltx.auth.store`` now call ``quiltx._core``. The
functions here are the Python they replaced (paths and ``normalize_dns`` from
quiltx 0.23.1; the file I/O from 0.24.0; the keyring get/store/delete/list
from the #152 merge), so ``tests/test_core_parity.py`` can run old and new on
the same inputs. Nothing under ``quiltx/`` imports this module.
"""

from __future__ import annotations

import json
import os
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


# ---------------------------------------------------------------------------
# File-backed store (copied from quiltx.auth.store at 0.24.0, with the path
# taken as an argument instead of going through _fallback_path / _index_path)
# ---------------------------------------------------------------------------


def read_fallback(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def write_fallback(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Tighten parent dir mode in case it pre-existed at a looser umask.
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    payload = json.dumps(data, indent=2).encode("utf-8")
    # Open with mode 0o600 from the start so the secret never sits at the
    # default umask between create and chmod (TOCTOU window on shared hosts).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    # If the file pre-existed at looser perms (older quiltx), tighten it now.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_index(path: Path) -> list:
    if not path.exists():
        return []
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(result, list):
            return result
        return []
    except (json.JSONDecodeError, OSError):
        return []


def write_index(path: Path, entries: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Tighten parent dir mode in case it pre-existed at a looser umask:
    # the index leaks DNS names (not secrets), but on a shared host that is
    # still better kept private. Mirrors the pattern in _write_fallback.
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    path.write_text(json.dumps(entries), encoding="utf-8")


def add_to_index(path: Path, dns: str) -> None:
    entries = read_index(path)
    if dns not in entries:
        entries.append(dns)
        write_index(path, entries)


def remove_from_index(path: Path, dns: str) -> None:
    entries = read_index(path)
    if dns in entries:
        entries.remove(dns)
        write_index(path, entries)


def get_fallback(path: Path, dns: str) -> dict | None:
    data = read_fallback(path)
    entry = data.get(dns)
    if entry is None or "api_key" not in entry:
        return None
    return entry


def store_fallback(
    path: Path,
    dns: str,
    api_key: str,
    name: str | None = None,
    expires_at: int | None = None,
) -> None:
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("API key is empty")
    if not api_key.startswith("qk_"):
        raise ValueError(
            "API key does not start with 'qk_'. Quilt API keys begin with "
            "'qk_' — paste the secret shown after creating a key in the "
            "catalog UI under Profile → API Keys."
        )
    payload = {
        "api_key": api_key,
        "name": name,
        "expires_at": expires_at,
    }
    data = read_fallback(path)
    data[dns] = payload
    write_fallback(path, data)


def delete_fallback(path: Path, dns: str) -> None:
    data = read_fallback(path)
    if dns in data:
        data.pop(dns)
        write_fallback(path, data)


def list_fallback(path: Path) -> list[tuple[str, dict]]:
    results: list[tuple[str, dict]] = []
    data = read_fallback(path)
    for dns, entry in data.items():
        if "api_key" in entry:
            results.append((dns, entry))
    return results


# ---------------------------------------------------------------------------
# Keyring-backed store (copied from quiltx.auth.store at the #152 merge, with
# the keyring object, paths, and use_keyring flag taken as arguments)
# ---------------------------------------------------------------------------


def get(
    dns: str,
    *,
    use_keyring: bool,
    fallback_path: Path,
    backend: object | None = None,
) -> dict | None:
    if use_keyring:
        raw = backend.get_password(*keyring_entry(dns))  # type: ignore[union-attr]
        if raw is None:
            return None
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(entry, dict) or "api_key" not in entry:
            return None
        return entry
    return get_fallback(fallback_path, dns)


def store(
    dns: str,
    api_key: str,
    *,
    name: str | None = None,
    expires_at: int | None = None,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
    backend: object | None = None,
) -> None:
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("API key is empty")
    if not api_key.startswith("qk_"):
        raise ValueError(
            "API key does not start with 'qk_'. Quilt API keys begin with "
            "'qk_' — paste the secret shown after creating a key in the "
            "catalog UI under Profile → API Keys."
        )
    payload = {
        "api_key": api_key,
        "name": name,
        "expires_at": expires_at,
    }
    if use_keyring:
        backend.set_password(*keyring_entry(dns), json.dumps(payload))  # type: ignore[union-attr]
        add_to_index(index_path, dns)
    else:
        store_fallback(fallback_path, dns, api_key, name, expires_at)


def delete(
    dns: str,
    *,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
    backend: object | None = None,
) -> None:
    if use_keyring:
        import keyring.errors

        try:
            backend.delete_password(*keyring_entry(dns))  # type: ignore[union-attr]
        except keyring.errors.PasswordDeleteError:
            pass
        remove_from_index(index_path, dns)
    else:
        delete_fallback(fallback_path, dns)


def catalog_list(
    *,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
    backend: object | None = None,
) -> list[tuple[str, dict]]:
    if use_keyring:
        results: list[tuple[str, dict]] = []
        for dns in read_index(index_path):
            entry = get(
                dns, use_keyring=True, fallback_path=fallback_path, backend=backend
            )
            if entry is not None:
                results.append((dns, entry))
        return results
    return list_fallback(fallback_path)
