"""The only importer of the compiled ``quiltx._core`` extension.

Everything Rust-backed that auth needs goes through this module, so the
boundary between the Python auth code and the Rust core is one file. The core
is required: catalog-name normalization (``normalize_dns``) runs on every CLI
command that takes a catalog, and the credential store's file paths and keyring
key come from it, so a missing extension is an error at import, with a message
that says how to fix it, rather than a degraded mode.
"""

from __future__ import annotations

from pathlib import Path

try:
    from quiltx import _core
except ImportError as exc:  # pragma: no cover - only without the compiled core
    raise ImportError(
        "quiltx's compiled core (quiltx._core) is missing. Reinstall quiltx from a "
        "wheel (pip install --force-reinstall quiltx); from a source checkout run "
        "`uv sync`, which builds it and needs a Rust toolchain (1.85 or newer)."
    ) from exc


def core_version() -> str:
    """Version of the Rust crate behind ``quiltx._core``."""
    return _core.core_version()


def ping(message: str) -> str:
    """Round-trip *message* through Rust; returns ``pong:<message>``."""
    return _core.ping(message)


def normalize_dns(value: str, insecure: bool = False) -> str:
    """Bare lowercase DNS name for a catalog identifier; raises ``ValueError``."""
    try:
        return _core.normalize_dns(value, insecure)
    except UnicodeEncodeError as exc:
        # A lone surrogate (an undecodable command-line byte) cannot cross into Rust.
        raise ValueError(
            "catalog DNS name is not valid text (it contains bytes that are not UTF-8)"
        ) from exc


def credentials_file() -> Path:
    """The ``credentials.json`` fallback file under quiltx's data directory."""
    return Path(_core.credentials_file())


def credentials_index_file() -> Path:
    """The ``credentials_index.json`` file that lists keyring-stored catalogs."""
    return Path(_core.credentials_index_file())


def keyring_entry(dns: str) -> tuple[str, str]:
    """``(service, username)`` of the OS-keyring entry for *dns*."""
    return _core.keyring_entry(dns)
