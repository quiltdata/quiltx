"""Tests for quiltx.auth credential resolver."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from quiltx import auth, credentials
from quiltx.stack import Catalog

FAKE_CATALOG = Catalog(
    catalog_name="nightly.quilttest.com",
    catalog_url="https://nightly.quilttest.com",
    source="flag",
)


def _no_keyring(monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)


def _tmp_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)


# ---------------------------------------------------------------------------
# CLI ladder
# ---------------------------------------------------------------------------


def test_cli_flags(monkeypatch):
    """--username/--password flags are top priority."""
    args = SimpleNamespace(username="alice", password="pass1", no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.username == "alice"
    assert result.secret == "pass1"
    assert result.source == "flag"


def test_cli_env_vars(monkeypatch):
    """QUILTX_USERNAME/QUILTX_PASSWORD are used when no flags."""
    monkeypatch.setenv("QUILTX_USERNAME", "env_user")
    monkeypatch.setenv("QUILTX_PASSWORD", "env_pass")
    args = SimpleNamespace(username=None, password=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.username == "env_user"
    assert result.source == "env"


def test_cli_env_vars_cleared(monkeypatch, tmp_path):
    """No env vars and no keyring entry → CredentialError in headless mode."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(username=None, password=None, no_prompt=True)
    with pytest.raises(auth.CredentialError, match="No credentials available"):
        auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_keyring(monkeypatch, tmp_path):
    """Keyring entry is found at step 3."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "keyring_user", "keyring_pass")
    args = SimpleNamespace(username=None, password=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.username == "keyring_user"
    assert result.source == "keyring"


def test_cli_prompt(monkeypatch, tmp_path, capsys):
    """Interactive prompt is used when TTY + no flags/env/keyring."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(username=None, password=None, no_prompt=False)

    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("builtins.input", return_value="prompted_user"),
        patch("getpass.getpass", return_value="prompted_pass"),
    ):
        result = auth.resolve_cli(FAKE_CATALOG, args)

    assert result.username == "prompted_user"
    assert result.source == "prompt"
    # Should have been stored in keyring
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["username"] == "prompted_user"


def test_cli_no_prompt_flag_blocks_interactive(monkeypatch, tmp_path):
    """--no-prompt suppresses the interactive prompt."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(username=None, password=None, no_prompt=True)
    with pytest.raises(auth.CredentialError):
        auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_quiltx_no_prompt_env(monkeypatch, tmp_path):
    """QUILTX_NO_PROMPT=1 env var suppresses interactive prompt."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    monkeypatch.setenv("QUILTX_NO_PROMPT", "1")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(username=None, password=None, no_prompt=False)
    with pytest.raises(auth.CredentialError):
        auth.resolve_cli(FAKE_CATALOG, args)


# ---------------------------------------------------------------------------
# API ladder
# ---------------------------------------------------------------------------


def test_api_env_vars(monkeypatch):
    """API resolver uses env vars."""
    monkeypatch.setenv("QUILTX_USERNAME", "api_user")
    monkeypatch.setenv("QUILTX_PASSWORD", "api_pass")
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.username == "api_user"
    assert result.source == "env"


def test_api_keyring(monkeypatch, tmp_path):
    """API resolver uses keyring after env vars."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "api_kring_user", "api_kring_pass")
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.username == "api_kring_user"
    assert result.source == "keyring"


def test_api_no_prompt(monkeypatch, tmp_path):
    """API resolver never prompts — raises CredentialError."""
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    with pytest.raises(auth.CredentialError):
        auth.resolve_api(FAKE_CATALOG)


def test_api_kwargs_take_priority(monkeypatch, tmp_path):
    """resolve_api(username=..., password=...) overrides env and keyring."""
    monkeypatch.setenv("QUILTX_USERNAME", "env_user")
    monkeypatch.setenv("QUILTX_PASSWORD", "env_pass")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "stored_user", "stored_pass")

    result = auth.resolve_api(FAKE_CATALOG, username="kw_user", password="kw_pass")
    assert result.username == "kw_user"
    assert result.secret == "kw_pass"
    assert result.source == "flag"


def test_api_kwargs_partial_falls_through(monkeypatch, tmp_path):
    """Username without password falls through to env/keyring (must appear together)."""
    monkeypatch.setenv("QUILTX_USERNAME", "env_user")
    monkeypatch.setenv("QUILTX_PASSWORD", "env_pass")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)

    result = auth.resolve_api(FAKE_CATALOG, username="kw_user")
    assert result.source == "env"
