"""Tests for `quiltx catalog list` and `quiltx catalog forget`."""

from __future__ import annotations

import pytest

from quiltx import credentials, userconfig
from quiltx.tools.catalog import forget as forget_cmd
from quiltx.tools.catalog import list_ as list_cmd


def _setup_no_keyring(monkeypatch, tmp_path):
    """Use file fallback + tmp_path for all credential storage."""
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")


# ---------------------------------------------------------------------------
# catalog list
# ---------------------------------------------------------------------------


def test_list_empty(tmp_path, monkeypatch, capsys):
    """Empty list shows 'No catalogs known'."""
    _setup_no_keyring(monkeypatch, tmp_path)
    result = list_cmd.main([])
    assert result == 0
    captured = capsys.readouterr()
    assert "No catalogs known" in captured.out


def test_list_shows_entries(tmp_path, monkeypatch, capsys):
    """Stored entries appear in list output without secrets."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("alpha.example.com", "alice", "s3cr3t1")
    credentials.set("beta.example.com", "bob", "s3cr3t2")

    result = list_cmd.main([])
    assert result == 0
    captured = capsys.readouterr()
    assert "alpha.example.com" in captured.out
    assert "beta.example.com" in captured.out
    assert "alice" in captured.out
    assert "bob" in captured.out
    # Secrets must not appear
    assert "s3cr3t1" not in captured.out
    assert "s3cr3t2" not in captured.out


# ---------------------------------------------------------------------------
# catalog forget
# ---------------------------------------------------------------------------


def test_forget_removes_entry(tmp_path, monkeypatch, capsys):
    """forget removes the keyring entry and prints confirmation."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "alice", "pass")

    result = forget_cmd.main(["nightly.quilttest.com"])
    assert result == 0
    captured = capsys.readouterr()
    assert "Forgot nightly.quilttest.com" in captured.out
    assert not credentials.has_credentials("nightly.quilttest.com")


def test_forget_idempotent(tmp_path, monkeypatch, capsys):
    """Forgetting an unknown catalog is idempotent (no error)."""
    _setup_no_keyring(monkeypatch, tmp_path)
    result = forget_cmd.main(["unknown.example.com"])
    assert result == 0
    captured = capsys.readouterr()
    assert "Forgot unknown.example.com" in captured.out


def test_forget_url_normalised(tmp_path, monkeypatch):
    """Full URL is normalised before deletion."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "alice", "pass")

    result = forget_cmd.main(["https://nightly.quilttest.com/"])
    assert result == 0
    assert not credentials.has_credentials("nightly.quilttest.com")


def test_forget_http_rejected(tmp_path, monkeypatch, capsys):
    """http:// identifier is rejected."""
    _setup_no_keyring(monkeypatch, tmp_path)
    result = forget_cmd.main(["http://nightly.quilttest.com"])
    assert result == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err


def test_forget_does_not_touch_default(tmp_path, monkeypatch):
    """Forgetting the default catalog does NOT auto-elect another."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "alice", "pass")
    userconfig.set_default_catalog("nightly.quilttest.com")

    forget_cmd.main(["nightly.quilttest.com"])

    # Default is still pointing at nightly — the spec says forget does not
    # modify the default; the next un-flagged command surfaces the "no creds" error.
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"
