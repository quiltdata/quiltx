"""Tests for `quiltx catalog default` CLI command."""

from __future__ import annotations

from quiltx import credentials, userconfig
from quiltx.tools.catalog import default as default_cmd


def _setup_no_keyring(monkeypatch, tmp_path):
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")


def test_default_no_arg_no_config(tmp_path, monkeypatch, capsys):
    """No arg + no default stored → error message, exit 1."""
    import sys
    import types

    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.delenv("QUILTX_CATALOG", raising=False)
    # Prevent bootstrap from reading a real quilt3 config
    fake_quilt3 = types.SimpleNamespace(config=lambda: {})
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    result = default_cmd.main([])
    assert result == 1
    captured = capsys.readouterr()
    assert "No default catalog configured" in captured.err


def test_default_no_arg_shows_current(tmp_path, monkeypatch, capsys):
    """No arg + default stored → prints current DNS, exit 0."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    userconfig.set_default_catalog("nightly.quilttest.com")

    result = default_cmd.main([])
    assert result == 0
    captured = capsys.readouterr()
    assert "nightly.quilttest.com" in captured.out


def test_default_set_dns(tmp_path, monkeypatch, capsys):
    """Passing a known DNS sets the default catalog."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_value")

    result = default_cmd.main(["nightly.quilttest.com"])
    assert result == 0
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"
    captured = capsys.readouterr()
    assert "nightly.quilttest.com" in captured.out


def test_default_set_url_normalised(tmp_path, monkeypatch):
    """A full URL is normalised to DNS before storing."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_value")

    result = default_cmd.main(["https://nightly.quilttest.com/"])
    assert result == 0
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"


def test_default_set_unknown_catalog_triggers_login(tmp_path, monkeypatch, capsys):
    """Setting default to an unknown DNS delegates to `catalog login` (B.3:
    auth on first config validates that the catalog is reachable)."""
    _setup_no_keyring(monkeypatch, tmp_path)

    # Headless with no auth flags: login errors out with exit 2.
    result = default_cmd.main(["--no-prompt", "unknown.example.com"])
    assert result == 2
    captured = capsys.readouterr()
    assert "Logging in" in captured.err
    assert "--username" in captured.err or "--api-key" in captured.err


def test_default_set_unknown_catalog_with_api_key_succeeds(
    tmp_path, monkeypatch, capsys
):
    """When --api-key is provided for an unknown DNS, the login flow stores it
    and `default` proceeds."""
    _setup_no_keyring(monkeypatch, tmp_path)

    result = default_cmd.main(
        ["--no-prompt", "unknown.example.com", "--api-key", "qk_paste"]
    )
    assert result == 0
    assert userconfig.get_default_catalog() == "unknown.example.com"
    assert credentials.get("unknown.example.com") is not None


def test_default_set_http_rejected(tmp_path, monkeypatch, capsys):
    """http:// identifiers are rejected."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    result = default_cmd.main(["http://nightly.quilttest.com"])
    assert result == 1
    captured = capsys.readouterr()
    assert "http://" in captured.err or "not supported" in captured.err


def test_default_clear(tmp_path, monkeypatch, capsys):
    """--clear removes the stored default."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    userconfig.set_default_catalog("nightly.quilttest.com")

    result = default_cmd.main(["--clear"])
    assert result == 0
    assert userconfig.get_default_catalog() is None
    captured = capsys.readouterr()
    assert "cleared" in captured.out.lower()


def test_default_clear_idempotent(tmp_path, monkeypatch):
    """--clear when nothing set is a no-op with exit 0."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    result = default_cmd.main(["--clear"])
    assert result == 0
