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

import functools
import json
import sys
from pathlib import Path
from typing import TypedDict, cast

from quiltx.auth import _native


class CredentialEntry(TypedDict, total=False):
    api_key: str
    name: str | None
    expires_at: int | None


# ---------------------------------------------------------------------------
# Keyring backend detection
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=None)
def _keyring_available() -> bool:
    """Return True if a real (non-fail) keyring backend is active.

    Cached because the backend cannot change at runtime and
    ``keyring.get_keyring()`` may trigger D-Bus / OS-keychain
    initialization on first call (per-op overhead is undesirable
    since this is consulted on every get/store/delete/list).
    """
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
    return _native.credentials_file()


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
    return _native.read_fallback(_fallback_path())


def _write_fallback(data: dict[str, CredentialEntry]) -> None:
    _native.write_fallback(_fallback_path(), data)


# ---------------------------------------------------------------------------
# Index file for keyring-backed list()
# ---------------------------------------------------------------------------
# keyring has no enumerate-all API. We maintain a lightweight
# user_data_path("quiltx")/credentials_index.json that tracks which DNS
# names we've stored. Written on set(), pruned on delete().


def _index_path() -> Path:
    return _native.credentials_index_file()


def _read_index() -> list[str]:
    return _native.read_index(_index_path())


def _write_index(entries: list[str]) -> None:
    _native.write_index(_index_path(), entries)


def _add_to_index(dns: str) -> None:
    _native.add_to_index(_index_path(), dns)


def _remove_from_index(dns: str) -> None:
    _native.remove_from_index(_index_path(), dns)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get(dns: str) -> CredentialEntry | None:
    """Return stored credentials for *dns*, or None if not found."""
    if _keyring_available():
        import keyring

        raw = keyring.get_password(*_native.keyring_entry(dns))
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
        return cast(CredentialEntry | None, _native.get_fallback(_fallback_path(), dns))


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

        keyring.set_password(*_native.keyring_entry(dns), serialised)
        _add_to_index(dns)
    else:
        _warn_file_fallback()
        _native.store_fallback(
            _fallback_path(), dns, api_key, name=name, expires_at=expires_at
        )


def delete(dns: str) -> None:
    """Delete credentials for *dns* (idempotent)."""
    if _keyring_available():
        import keyring
        import keyring.errors

        try:
            keyring.delete_password(*_native.keyring_entry(dns))
        except keyring.errors.PasswordDeleteError:
            pass  # already gone — idempotent
        _remove_from_index(dns)
    else:
        _native.delete_fallback(_fallback_path(), dns)


def catalog_list() -> list[tuple[str, CredentialEntry]]:
    """List known DNS entries as ``(dns, entry)``."""
    results: list[tuple[str, CredentialEntry]] = []
    if _keyring_available():
        for dns in _read_index():
            entry = get(dns)
            if entry is not None:
                results.append((dns, entry))
    else:
        return cast(
            list[tuple[str, CredentialEntry]], _native.list_fallback(_fallback_path())
        )
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
