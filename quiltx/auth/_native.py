"""The only importer of ``quiltx._core``.

Everything Rust-backed that auth needs goes through this module, so the
boundary between the Python auth code and the Rust core is one file. The core
is required: catalog-name normalization (``normalize_dns``) runs on every CLI
command that takes a catalog, and the credential store and registry HTTP
come from it, so a missing extension is an error at import, with a
message that says how to fix it, rather than a degraded mode.
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


def read_fallback(path: Path) -> dict:
    """Read ``credentials.json``; a missing file is ``{}``."""
    return _core.read_fallback(path)


def write_fallback(path: Path, data: dict) -> None:
    """Write ``credentials.json`` at mode 0600, in Python's ``indent=2`` form."""
    _core.write_fallback(path, data)


def read_index(path: Path) -> list[str]:
    """Read ``credentials_index.json``; a missing or non-list file is ``[]``."""
    return _core.read_index(path)


def write_index(path: Path, entries: list[str]) -> None:
    """Write ``credentials_index.json`` (compact JSON, process umask)."""
    _core.write_index(path, entries)


def add_to_index(path: Path, dns: str) -> None:
    """Append *dns* to the index if it is not already listed."""
    _core.add_to_index(path, dns)


def remove_from_index(path: Path, dns: str) -> None:
    """Remove *dns* from the index if it is listed (idempotent)."""
    _core.remove_from_index(path, dns)


def get_fallback(path: Path, dns: str) -> dict | None:
    """File-backend ``get``: the entry for *dns*, or ``None``."""
    return _core.get_fallback(path, dns)


def store_fallback(
    path: Path,
    dns: str,
    api_key: str,
    name: str | None = None,
    expires_at: int | None = None,
) -> None:
    """File-backend ``store``: validate the key and write the entry."""
    _core.store_fallback(path, dns, api_key, name, expires_at)


def delete_fallback(path: Path, dns: str) -> None:
    """File-backend ``delete`` (idempotent)."""
    _core.delete_fallback(path, dns)


def list_fallback(path: Path) -> list[tuple[str, dict]]:
    """File-backend ``catalog_list``: ``(dns, entry)`` in file order."""
    return _core.list_fallback(path)


def get_credential(dns: str, use_keyring: bool, fallback_path: Path) -> dict | None:
    """Public ``get``: OS keyring or the file fallback, chosen by *use_keyring*."""
    return _core.get_credential(dns, use_keyring, fallback_path)


def store_credential(
    dns: str,
    api_key: str,
    name: str | None,
    expires_at: int | None,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
) -> None:
    """Public ``store``: validate the key and write it."""
    _core.store_credential(
        dns, api_key, name, expires_at, use_keyring, fallback_path, index_path
    )


def delete_credential(
    dns: str, use_keyring: bool, fallback_path: Path, index_path: Path
) -> None:
    """Public ``delete`` (idempotent)."""
    _core.delete_credential(dns, use_keyring, fallback_path, index_path)


def list_credentials(
    use_keyring: bool, fallback_path: Path, index_path: Path
) -> list[tuple[str, dict]]:
    """Public ``catalog_list``."""
    return _core.list_credentials(use_keyring, fallback_path, index_path)


def resolve_registry_url(catalog_url: str) -> str:
    """Registry base URL advertised by ``<catalog_url>/config.json``."""
    return _core.resolve_registry_url(catalog_url)


def acquire_refresh_token(registry_url: str, username: str, password: str) -> str:
    """POST username/password to ``<registry_url>/api/login``."""
    return _core.acquire_refresh_token(registry_url, username, password)


def exchange_refresh_token_for_access_token(
    registry_url: str, refresh_token: str
) -> str:
    """Trade a refresh_token for an access_token (form-encoded ``/api/token``)."""
    return _core.exchange_refresh_token_for_access_token(registry_url, refresh_token)


def create_api_key(
    registry_url: str, access_token: str, name: str, expires_in_days: int
) -> dict:
    """Mint a ``qk_`` API key via GraphQL ``apiKeyCreate``."""
    return _core.create_api_key(registry_url, access_token, name, expires_in_days)


def validate_api_key(registry_url: str, api_key: str) -> None:
    """Confirm *api_key* is accepted; *registry_url* is already resolved."""
    _core.validate_api_key(registry_url, api_key)


def mint_registry_credentials(registry_url: str) -> dict:
    """GET ``<registry_url>/api/auth/get_credentials`` and map the STS payload."""
    return _core.mint_registry_credentials(registry_url)
