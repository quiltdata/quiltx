"""Tests for @catalog_command with active ensure_auth (§4)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from quiltx import credentials
from quiltx.stack import Catalog, catalog_command, resolve_catalog_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _fake_catalog(auth_required: bool = True) -> Catalog:
    return Catalog(
        catalog_name="test.example.com",
        catalog_url="https://test.example.com",
        source="flag",
        auth_required=auth_required,
    )


# ---------------------------------------------------------------------------
# ensure_auth no-op when auth_required=False
# ---------------------------------------------------------------------------


def test_ensure_auth_noop_when_not_required():
    """ensure_auth() is a no-op when auth_required=False."""
    cat = _fake_catalog(auth_required=False)
    cat.ensure_auth()  # should not raise


# ---------------------------------------------------------------------------
# ensure_auth raises when no credentials and headless
# ---------------------------------------------------------------------------


def test_ensure_auth_raises_no_credentials(tmp_path, monkeypatch):
    """ensure_auth() raises when no credentials available in headless mode."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)

    cat = _fake_catalog(auth_required=True)
    with pytest.raises(ValueError, match="No credentials available"):
        cat.ensure_auth()


# ---------------------------------------------------------------------------
# ensure_auth uses stored credentials
# ---------------------------------------------------------------------------


def test_ensure_auth_uses_keyring_credentials(tmp_path, monkeypatch):
    """ensure_auth() retrieves credentials from keyring and binds quilt3."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)

    # Store a fake refresh token (long enough to pass validate check)
    fake_token = "eyJ" + "a" * 60  # looks like a JWT
    credentials.store("test.example.com", "alice", fake_token)

    validated = []
    logged_in = []

    def fake_validate(url, token):
        validated.append((url, token))
        return True  # treat as valid refresh token

    def fake_login_with_token(token):
        logged_in.append(token)

    def fake_set_global_config(url, **kw):
        pass

    cat = _fake_catalog(auth_required=True)

    with (
        patch("quiltx.quilt_auth.validate_refresh_token", fake_validate),
        patch("quiltx.quilt3_facade.login_with_token", fake_login_with_token),
        patch("quiltx.quilt3_facade.set_global_config", fake_set_global_config),
    ):
        cat.ensure_auth()

    assert len(validated) == 1
    assert len(logged_in) == 1
    assert logged_in[0] == fake_token


# ---------------------------------------------------------------------------
# ensure_auth exchanges password for refresh token
# ---------------------------------------------------------------------------


def test_ensure_auth_exchanges_password_for_token(tmp_path, monkeypatch):
    """When stored secret fails token validation, treat as password and acquire token."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)

    credentials.store("test.example.com", "alice", "plaintext-password")

    acquired = []
    logged_in = []

    def fake_validate(url, token):
        return False  # password fails validation

    def fake_acquire(url, username, password):
        acquired.append((url, username, password))
        return "new-refresh-token"

    def fake_login_with_token(token):
        logged_in.append(token)

    def fake_set_global_config(url, **kw):
        pass

    cat = _fake_catalog(auth_required=True)

    with (
        patch("quiltx.quilt_auth.validate_refresh_token", fake_validate),
        patch("quiltx.quilt_auth.acquire_refresh_token", fake_acquire),
        patch("quiltx.quilt3_facade.login_with_token", fake_login_with_token),
        patch("quiltx.quilt3_facade.set_global_config", fake_set_global_config),
    ):
        cat.ensure_auth()

    assert acquired == [("https://test.example.com", "alice", "plaintext-password")]
    assert logged_in == ["new-refresh-token"]
    # New token should be stored in keyring
    stored = credentials.get("test.example.com")
    assert stored is not None
    assert stored["secret"] == "new-refresh-token"


# ---------------------------------------------------------------------------
# @catalog_command retry uses ensure_auth
# ---------------------------------------------------------------------------


def test_catalog_command_retry_uses_ensure_auth(monkeypatch):
    """On auth failure, @catalog_command retries after ensure_auth."""
    call_count = 0
    ensure_auth_calls = []

    # Create a catalog with auth_required=False to bypass real credential lookup
    cat = Catalog(
        catalog_name="retry.example.com",
        catalog_url="https://retry.example.com",
        source="flag",
        auth_required=False,
    )
    monkeypatch.setattr(
        "quiltx.stack.resolve_catalog_context", lambda _catalog=None, **kw: cat
    )
    # Track ensure_auth calls
    monkeypatch.setattr(
        Catalog, "ensure_auth", lambda self, args=None: ensure_auth_calls.append(1)
    )

    @catalog_command
    def guarded(stack_arg: Catalog) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("Authentication failed.")
        return "ok"

    result = guarded()
    assert result == "ok"
    assert call_count == 2
