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
        # fail.Keyring and null.Keyring are both named just "Keyring";
        # distinguish them by module so headless Linux falls back to the file.
        module = type(backend).__module__
        return module not in {"keyring.backends.fail", "keyring.backends.null"}
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


# keyring has no enumerate-all API. credentials_index.json tracks which
# DNS names we've stored; Rust writes it on store() and prunes it on delete().


def _index_path() -> Path:
    return _native.credentials_index_file()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get(dns: str) -> CredentialEntry | None:
    """Return stored credentials for *dns*, or None if not found."""
    return cast(
        CredentialEntry | None,
        _native.get_credential(dns, _keyring_available(), _fallback_path()),
    )


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
    use_keyring = _keyring_available()
    if not use_keyring:
        _warn_file_fallback()
    _native.store_credential(
        dns,
        api_key,
        name,
        expires_at,
        use_keyring,
        _fallback_path(),
        _index_path(),
    )


def delete(dns: str) -> None:
    """Delete credentials for *dns* (idempotent)."""
    _native.delete_credential(
        dns, _keyring_available(), _fallback_path(), _index_path()
    )


def catalog_list() -> list[tuple[str, CredentialEntry]]:
    """List known DNS entries as ``(dns, entry)``."""
    return cast(
        list[tuple[str, CredentialEntry]],
        _native.list_credentials(_keyring_available(), _fallback_path(), _index_path()),
    )


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
