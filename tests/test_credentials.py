"""Tests for quiltx.credentials (keyring-backed + file fallback)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quiltx import credentials

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_no_keyring(monkeypatch):
    """Patch credentials so _keyring_available() returns False."""
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)


def _use_tmp_fallback(monkeypatch, tmp_path):
    """Redirect the file-fallback and index paths to tmp_path."""
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    # Reset the warn flag so tests don't bleed into each other
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)


# ---------------------------------------------------------------------------
# File-fallback tests (no keyring backend)
# ---------------------------------------------------------------------------


def test_file_fallback_get_none_when_missing(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)
    assert credentials.get("nightly.quilttest.com") is None


def test_file_fallback_set_and_get(tmp_path, monkeypatch, capsys):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("nightly.quilttest.com", "alice", "s3cr3t")
    result = credentials.get("nightly.quilttest.com")
    assert result is not None
    assert result["username"] == "alice"
    assert result["secret"] == "s3cr3t"

    # Warning should have been printed
    captured = capsys.readouterr()
    assert "WARNING" in captured.err


def test_file_fallback_delete_idempotent(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("nightly.quilttest.com", "alice", "s3cr3t")
    credentials.delete("nightly.quilttest.com")
    assert credentials.get("nightly.quilttest.com") is None
    # Second delete is a no-op
    credentials.delete("nightly.quilttest.com")


def test_file_fallback_has_credentials(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    assert not credentials.has_credentials("nightly.quilttest.com")
    credentials.set("nightly.quilttest.com", "alice", "s3cr3t")
    assert credentials.has_credentials("nightly.quilttest.com")


def test_file_fallback_list(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("a.example.com", "alice", "pass1")
    credentials.set("b.example.com", "bob", "pass2")

    entries = credentials.catalog_list()
    dns_list = [e[0] for e in entries]
    assert "a.example.com" in dns_list
    assert "b.example.com" in dns_list
    # Secrets must not be exposed
    for _, username, _ in entries:
        assert username in {"alice", "bob"}


def test_file_mode_600(tmp_path, monkeypatch):
    """File-fallback credentials file should be mode 0600."""
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("nightly.quilttest.com", "alice", "s3cr3t")
    cred_file = tmp_path / "credentials.json"
    assert cred_file.exists()
    mode = oct(cred_file.stat().st_mode)
    assert mode.endswith("600"), f"Expected 0600 mode, got {mode}"


# ---------------------------------------------------------------------------
# Index-backed list (keyring path)
# ---------------------------------------------------------------------------


def test_keyring_list_via_index(tmp_path, monkeypatch):
    """list() returns entries from the index when keyring is active."""
    monkeypatch.setattr(credentials, "_keyring_available", lambda: True)
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )

    stored: dict[str, str] = {}

    def fake_get_password(service, key):
        return stored.get(key)

    def fake_set_password(service, key, value):
        stored[key] = value

    def fake_delete_password(service, key):
        stored.pop(key, None)

    with (
        patch("keyring.get_password", fake_get_password),
        patch("keyring.set_password", fake_set_password),
        patch("keyring.delete_password", fake_delete_password),
    ):
        credentials.set("x.example.com", "charlie", "abc")
        entries = credentials.catalog_list()
        assert any(e[0] == "x.example.com" for e in entries)

        credentials.delete("x.example.com")
        entries = credentials.catalog_list()
        assert not any(e[0] == "x.example.com" for e in entries)
