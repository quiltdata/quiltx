"""Per-DNS API-key storage for quiltx.

Backed by the ``keyring`` package (cross-platform). On Linux without a
keyring backend, falls back to a file at
``user_data_path("quiltx")/credentials.json`` with mode 0600 and a loud
first-run warning.

Storage shape (per keyring entry, JSON-encoded), per spec [05 §3]:
    {"api_key": "qk_...", "name": <str|null>, "expires_at": <unix-ts|null>}

``name`` and ``expires_at`` are nullable — the paste-only bootstrap leaves
them ``null``. Future ``quiltx catalog login --create`` may populate them.

Service name in keyring: ``quiltx``
Username key: canonical DNS (e.g. ``nightly.quilttest.com``)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TypedDict

from platformdirs import user_data_path

_KEYRING_SERVICE = "quiltx"


class CredentialEntry(TypedDict, total=False):
    api_key: str
    name: str | None
    expires_at: int | None


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


def _read_fallback() -> dict[str, CredentialEntry]:
    path = _fallback_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write_fallback(data: dict[str, CredentialEntry]) -> None:
    path = _fallback_path()
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


# ---------------------------------------------------------------------------
# Index file for keyring-backed list()
# ---------------------------------------------------------------------------
# keyring has no enumerate-all API. We maintain a lightweight
# user_data_path("quiltx")/credentials_index.json that tracks which DNS
# names we've stored. Written on set(), pruned on delete().


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


def get(dns: str) -> CredentialEntry | None:
    """Return stored credentials for *dns*, or None if not found."""
    if _keyring_available():
        import keyring

        raw = keyring.get_password(_KEYRING_SERVICE, dns)
        if raw is None:
            return None
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(entry, dict) or "api_key" not in entry:
            return None
        return CredentialEntry(**entry)
    else:
        data = _read_fallback()
        entry = data.get(dns)
        if entry is None or "api_key" not in entry:
            return None
        return entry


def store(
    dns: str,
    api_key: str,
    *,
    name: str | None = None,
    expires_at: int | None = None,
) -> None:
    """Store *api_key* for *dns* with optional metadata.

    Validates the ``qk_`` prefix per spec [05 §3] (matches quilt3's own
    ``session.py`` prefix check). Raises ``ValueError`` for malformed input
    so a typo or paste of the wrong string never lands in the keyring.
    """
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("API key is empty")
    if not api_key.startswith("qk_"):
        raise ValueError(
            "API key does not start with 'qk_'. Quilt API keys begin with "
            "'qk_' — paste the secret shown after creating a key in the "
            "catalog UI under Profile → API Keys."
        )
    payload: CredentialEntry = {
        "api_key": api_key,
        "name": name,
        "expires_at": expires_at,
    }
    serialised = json.dumps(payload)
    if _keyring_available():
        import keyring

        keyring.set_password(_KEYRING_SERVICE, dns, serialised)
        _add_to_index(dns)
    else:
        _warn_file_fallback()
        data = _read_fallback()
        data[dns] = payload
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


def catalog_list() -> list[tuple[str, CredentialEntry]]:
    """List known DNS entries as ``(dns, entry)``."""
    results: list[tuple[str, CredentialEntry]] = []
    if _keyring_available():
        for dns in _read_index():
            entry = get(dns)
            if entry is not None:
                results.append((dns, entry))
    else:
        data = _read_fallback()
        for dns, entry in data.items():
            if "api_key" in entry:
                results.append((dns, entry))
    return results


def has_credentials(dns: str) -> bool:
    """Return True if credentials are stored for *dns*."""
    return get(dns) is not None


# PEP 562 module __getattr__: expose the spec-named ``set`` / ``list`` as
# module attributes without rebinding the builtins inside this file (which
# would break ``isinstance(x, list)`` and ``list[str]`` type annotations).
_PUBLIC_ALIASES = {"set": store, "list": catalog_list}


def __getattr__(name: str):
    try:
        return _PUBLIC_ALIASES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
