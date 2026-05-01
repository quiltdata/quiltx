"""Tests for quiltx.auth API-key resolver."""

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


def _clear_env(monkeypatch):
    monkeypatch.delenv("QUILTX_API_KEY", raising=False)
    monkeypatch.delenv("QUILTX_NO_PROMPT", raising=False)


# ---------------------------------------------------------------------------
# CLI ladder
# ---------------------------------------------------------------------------


def test_cli_flag(monkeypatch):
    """--api-key flag is top priority."""
    _clear_env(monkeypatch)
    args = SimpleNamespace(api_key="qk_flag", no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_flag"
    assert result.source == "flag"


def test_cli_env_var(monkeypatch):
    """QUILTX_API_KEY is used when no flag."""
    monkeypatch.setenv("QUILTX_API_KEY", "qk_env")
    args = SimpleNamespace(api_key=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_env"
    assert result.source == "env"


def test_cli_no_creds_raises_in_headless(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError, match="No API key available"):
        auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_keyring(monkeypatch, tmp_path):
    """Keyring entry is found at step 3."""
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_keyring")
    args = SimpleNamespace(api_key=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_keyring"
    assert result.source == "keyring"


def test_cli_skip_keyring(monkeypatch, tmp_path):
    """skip_keyring=True forces fallthrough to prompt/env even with stored entry."""
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_keyring")
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError, match="No API key available"):
        auth.resolve_cli(FAKE_CATALOG, args, skip_keyring=True)


def test_cli_prompt_stores_key(monkeypatch, tmp_path):
    """Interactive prompt stores the pasted API key."""
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=False)

    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("getpass.getpass", return_value="qk_prompted"),
    ):
        result = auth.resolve_cli(FAKE_CATALOG, args)

    assert result.api_key == "qk_prompted"
    assert result.source == "prompt"
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_prompted"
    # Paste-only bootstrap leaves metadata null per [05 §3].
    assert stored.get("name") is None
    assert stored.get("expires_at") is None


def test_cli_prompt_empty_rejected(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=False)
    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("getpass.getpass", return_value="   "),
    ):
        with pytest.raises(auth.CredentialError, match="Empty API key"):
            auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_no_prompt_flag_blocks_interactive(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError):
        auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_quiltx_no_prompt_env(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    monkeypatch.setenv("QUILTX_NO_PROMPT", "1")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=False)
    with pytest.raises(auth.CredentialError):
        auth.resolve_cli(FAKE_CATALOG, args)


# ---------------------------------------------------------------------------
# API ladder
# ---------------------------------------------------------------------------


def test_api_env_var(monkeypatch):
    monkeypatch.setenv("QUILTX_API_KEY", "qk_api_env")
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.api_key == "qk_api_env"
    assert result.source == "env"


def test_api_keyring(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_api_kring")
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.api_key == "qk_api_kring"
    assert result.source == "keyring"


def test_api_no_prompt_raises(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    with pytest.raises(auth.CredentialError):
        auth.resolve_api(FAKE_CATALOG)


def test_api_kwarg_takes_priority(monkeypatch, tmp_path):
    monkeypatch.setenv("QUILTX_API_KEY", "qk_env")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_stored")

    result = auth.resolve_api(FAKE_CATALOG, api_key="qk_kw")
    assert result.api_key == "qk_kw"
    assert result.source == "flag"


def test_api_skip_keyring(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_stored")
    with pytest.raises(auth.CredentialError):
        auth.resolve_api(FAKE_CATALOG, skip_keyring=True)
