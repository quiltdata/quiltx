"""Tests for @catalog_command with active ensure_auth (§4)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from quiltx import credentials
from quiltx.stack import Catalog, catalog_command

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


def _clear_env(monkeypatch):
    monkeypatch.delenv("QUILTX_API_KEY", raising=False)
    monkeypatch.delenv("QUILTX_NO_PROMPT", raising=False)


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
    cat = _fake_catalog(auth_required=False)
    cat.ensure_auth()  # should not raise


# ---------------------------------------------------------------------------
# ensure_auth raises when no credentials and headless
# ---------------------------------------------------------------------------


def test_ensure_auth_raises_no_credentials(tmp_path, monkeypatch):
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    _clear_env(monkeypatch)

    cat = _fake_catalog(auth_required=True)
    with pytest.raises(ValueError, match="No API key available"):
        cat.ensure_auth()


# ---------------------------------------------------------------------------
# ensure_auth uses stored API key
# ---------------------------------------------------------------------------


def test_ensure_auth_uses_keyring_api_key(tmp_path, monkeypatch):
    """ensure_auth() pulls API key from keyring and calls login_with_api_key."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    _clear_env(monkeypatch)

    credentials.store("test.example.com", "qk_stored")

    bound: list[str] = []
    logged_in: list[tuple[str, str]] = []

    cat = _fake_catalog(auth_required=True)

    with (
        patch(
            "quiltx.quilt3_facade.bind_active_catalog",
            lambda url: bound.append(url) or "TOKEN",
        ),
        patch(
            "quiltx.quilt3_facade.login_with_api_key",
            lambda key, catalog_url: logged_in.append((key, catalog_url)),
        ),
    ):
        cat.ensure_auth()

    assert bound == ["https://test.example.com"]
    assert logged_in == [("qk_stored", "https://test.example.com")]


# ---------------------------------------------------------------------------
# ensure_auth(skip_keyring=True) bypasses stored entry
# ---------------------------------------------------------------------------


def test_ensure_auth_skip_keyring_bypasses_stored(tmp_path, monkeypatch):
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    _clear_env(monkeypatch)

    credentials.store("test.example.com", "qk_stale")

    cat = _fake_catalog(auth_required=True)

    with pytest.raises(ValueError, match="No API key available"):
        cat.ensure_auth(skip_keyring=True)


# ---------------------------------------------------------------------------
# @catalog_command retry uses ensure_auth(skip_keyring=True)
# ---------------------------------------------------------------------------


def test_catalog_command_retry_skips_keyring(monkeypatch):
    """On auth failure, the retry calls ensure_auth(skip_keyring=True)."""
    call_count = 0
    ensure_auth_calls: list[dict] = []

    cat = Catalog(
        catalog_name="retry.example.com",
        catalog_url="https://retry.example.com",
        source="flag",
        auth_required=False,
    )
    monkeypatch.setattr(
        "quiltx.stack.resolve_catalog_context", lambda _catalog=None, **kw: cat
    )

    def fake_ensure_auth(self, args=None, *, skip_keyring=False):
        ensure_auth_calls.append({"skip_keyring": skip_keyring})

    monkeypatch.setattr(Catalog, "ensure_auth", fake_ensure_auth)

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
    # First ensure_auth from invoke(); retry skips keyring.
    assert any(c["skip_keyring"] for c in ensure_auth_calls)
