"""Per-DNS credential storage for quiltx.

Backed by the ``keyring`` package (cross-platform). On Linux without a
keyring backend, falls back to a file at
``user_data_path("quiltx")/credentials.json`` with mode 0600 and a loud
first-run warning.

Storage shape (per keyring entry, JSON-encoded):
    {"username": "<u>", "secret": "<password-or-refresh-token>"}

Service name in keyring: ``quiltx``
Username key: canonical DNS (e.g. ``nightly.quilttest.com``)
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Mapping

from platformdirs import user_data_path

_KEYRING_SERVICE = "quiltx"


# ---------------------------------------------------------------------------
# Keyring backend detection
# ---------------------------------------------------------------------------


def _keyring_available() -> bool:
    """Return True if a real (non-fail) keyring backend is active."""
    try:
        import keyring

        backend = keyring.get_keyring()
        # The 'fail' backend raises on every operation.
        name = type(backend).__name__.lower()
        return "fail" not in name and "null" not in name
    except Exception:
        return False


# ---------------------------------------------------------------------------
# File-based fallback (Linux CI / no keyring backend)
# ---------------------------------------------------------------------------


def _fallback_path() -> Path:
    return user_data_path("quiltx") / "credentials.json"


_FILE_FALLBACK_WARNED = False


def _warn_file_fallback() -> None:
    global _FILE_FALLBACK_WARNED
    if not _FILE_FALLBACK_WARNED:
        print(
            "WARNING: No system keyring backend found. "
            "Credentials will be stored in plain JSON at "
            f"{_fallback_path()} (mode 0600). "
            "Install a keyring backend (e.g. 'secretservice' on Linux) "
            "to suppress this warning.",
            file=sys.stderr,
        )
        _FILE_FALLBACK_WARNED = True


def _read_fallback() -> dict[str, dict[str, str]]:
    path = _fallback_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_fallback(data: dict[str, dict[str, str]]) -> None:
    path = _fallback_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Index file for keyring-backed list()
# ---------------------------------------------------------------------------
# keyring has no enumerate-all API.  We maintain a lightweight
# user_data_path("quiltx")/credentials_index.json that tracks which DNS
# names we've stored.  Written on set(), pruned on delete().


def _index_path() -> Path:
    return user_data_path("quiltx") / "credentials_index.json"


def _read_index() -> list[str]:
    path = _index_path()
    if not path.exists():
        return []
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(result, list):
            return result
        return []
    except (json.JSONDecodeError, OSError):
        return []


def _write_index(entries: list[str]) -> None:
    path = _index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries), encoding="utf-8")


def _add_to_index(dns: str) -> None:
    entries = _read_index()
    if dns not in entries:
        entries.append(dns)
        _write_index(entries)


def _remove_from_index(dns: str) -> None:
    entries = _read_index()
    if dns in entries:
        entries.remove(dns)
        _write_index(entries)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get(dns: str) -> Mapping[str, str] | None:
    """Return stored credentials for *dns*, or None if not found."""
    if _keyring_available():
        import keyring

        raw = keyring.get_password(_KEYRING_SERVICE, dns)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    else:
        data = _read_fallback()
        return data.get(dns)


def store(dns: str, username: str, secret: str) -> None:
    """Store credentials for *dns*."""
    payload = json.dumps({"username": username, "secret": secret})
    if _keyring_available():
        import keyring

        keyring.set_password(_KEYRING_SERVICE, dns, payload)
        _add_to_index(dns)
    else:
        _warn_file_fallback()
        data = _read_fallback()
        data[dns] = {"username": username, "secret": secret}
        _write_fallback(data)


def delete(dns: str) -> None:
    """Delete credentials for *dns* (idempotent)."""
    if _keyring_available():
        import keyring
        import keyring.errors

        try:
            keyring.delete_password(_KEYRING_SERVICE, dns)
        except keyring.errors.PasswordDeleteError:
            pass  # already gone — idempotent
        _remove_from_index(dns)
    else:
        data = _read_fallback()
        if dns in data:
            data.pop(dns)
            _write_fallback(data)


def catalog_list() -> list[tuple[str, str, datetime | None]]:
    """List known DNS entries as (dns, username, last_used).

    ``last_used`` is always None for now — keyring backends don't expose it.
    """
    results: list[tuple[str, str, datetime | None]] = []
    if _keyring_available():
        for dns in _read_index():
            entry = get(dns)
            if entry is not None:
                results.append((dns, str(entry.get("username", "")), None))
    else:
        data = _read_fallback()
        for dns, creds in data.items():
            results.append((dns, creds.get("username", ""), None))
    return results


def has_credentials(dns: str) -> bool:
    """Return True if credentials are stored for *dns*."""
    return get(dns) is not None


# Compatibility alias: the public API was ``set`` in earlier drafts.
# Using ``store`` avoids shadowing the builtin.
set = store  # noqa: A001
