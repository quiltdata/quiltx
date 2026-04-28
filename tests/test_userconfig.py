"""Tests for quiltx.userconfig (default catalog storage)."""

from __future__ import annotations


from quiltx import userconfig


def test_get_default_catalog_none_when_missing(tmp_path, monkeypatch):
    """Returns None when config file doesn't exist."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    assert userconfig.get_default_catalog() is None


def test_set_and_get_default_catalog(tmp_path, monkeypatch):
    """set_default_catalog stores the DNS; get_default_catalog retrieves it."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    userconfig.set_default_catalog("nightly.quilttest.com")
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"


def test_clear_default_catalog(tmp_path, monkeypatch):
    """clear_default_catalog removes the key; file remains."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    userconfig.set_default_catalog("nightly.quilttest.com")
    userconfig.clear_default_catalog()
    assert userconfig.get_default_catalog() is None
    # File should still exist (just without the key)
    assert (tmp_path / "config.json").exists()


def test_clear_is_idempotent(tmp_path, monkeypatch):
    """Clearing when nothing is set is a no-op."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    userconfig.clear_default_catalog()  # should not raise
    assert userconfig.get_default_catalog() is None


def test_set_overwrites_existing(tmp_path, monkeypatch):
    """set_default_catalog replaces a previously stored value."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    userconfig.set_default_catalog("old.example.com")
    userconfig.set_default_catalog("new.example.com")
    assert userconfig.get_default_catalog() == "new.example.com"


def test_other_keys_preserved(tmp_path, monkeypatch):
    """set/clear only touches default_catalog; other keys in the file are preserved."""
    import json

    config_file = tmp_path / "config.json"
    monkeypatch.setattr(userconfig, "_config_path", lambda: config_file)

    # Pre-populate with an unrelated key
    config_file.write_text(json.dumps({"other_key": "other_value"}))

    userconfig.set_default_catalog("nightly.quilttest.com")
    data = json.loads(config_file.read_text())
    assert data["other_key"] == "other_value"
    assert data["default_catalog"] == "nightly.quilttest.com"

    userconfig.clear_default_catalog()
    data = json.loads(config_file.read_text())
    assert data["other_key"] == "other_value"
    assert "default_catalog" not in data


def test_bootstrap_from_quilt3_config(tmp_path, monkeypatch):
    """_lookup_default_dns bootstraps from quilt3.config() on first run."""
    import sys
    import types

    from quiltx import stack as stack_lib

    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    fake_config = {"navigator_url": "https://nightly.quilttest.com"}
    fake_quilt3 = types.SimpleNamespace(config=lambda: fake_config)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    dns = stack_lib._lookup_default_dns()
    assert dns == "nightly.quilttest.com"
    # Should have been persisted
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"


def test_bootstrap_does_not_overwrite_existing(tmp_path, monkeypatch):
    """Bootstrap rule does not fire when a default is already stored."""
    import sys
    import types

    from quiltx import stack as stack_lib

    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    userconfig.set_default_catalog("existing.example.com")

    fake_config = {"navigator_url": "https://other.example.com"}
    fake_quilt3 = types.SimpleNamespace(config=lambda: fake_config)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    dns = stack_lib._lookup_default_dns()
    assert dns == "existing.example.com"
