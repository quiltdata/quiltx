"""Tests for `quiltx catalog default` CLI command."""

from __future__ import annotations

from quiltx import userconfig
from quiltx.tools.catalog import default as default_cmd


def test_default_no_arg_no_config(tmp_path, monkeypatch, capsys):
    """No arg + no default stored → error message, exit 1."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

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
    """Passing a DNS sets the default catalog."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    result = default_cmd.main(["nightly.quilttest.com"])
    assert result == 0
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"
    captured = capsys.readouterr()
    assert "nightly.quilttest.com" in captured.out


def test_default_set_url_normalised(tmp_path, monkeypatch):
    """A full URL is normalised to DNS before storing."""
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")

    result = default_cmd.main(["https://nightly.quilttest.com/"])
    assert result == 0
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"


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
