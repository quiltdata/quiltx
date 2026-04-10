from __future__ import annotations

import sys
import types

import pytest

import quiltx


def test_get_catalog_config(monkeypatch) -> None:
    """Test get_catalog_config returns quilt3.config()."""
    fake_config = {"navigator_url": "https://example.test", "region": "us-east-1"}

    def _config_return():
        return fake_config

    fake_quilt3 = types.SimpleNamespace(config=_config_return)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    config = quiltx.get_catalog_config()

    assert config == fake_config


def test_get_catalog_config_raises_when_not_configured(monkeypatch) -> None:
    """Test get_catalog_config raises ValueError when no catalog configured."""

    def _config_return():
        return {}

    fake_quilt3 = types.SimpleNamespace(config=_config_return)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    with pytest.raises(ValueError, match="No Quilt catalog configured"):
        quiltx.get_catalog_config()


def test_get_catalog_url(monkeypatch) -> None:
    """Test get_catalog_url extracts navigator_url."""
    fake_config = {"navigator_url": "https://example.test", "region": "us-east-1"}

    def _config_return():
        return fake_config

    fake_quilt3 = types.SimpleNamespace(config=_config_return)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    url = quiltx.get_catalog_url()

    assert url == "https://example.test"


def test_get_catalog_region(monkeypatch) -> None:
    """Test get_catalog_region extracts region."""
    fake_config = {"navigator_url": "https://example.test", "region": "us-east-1"}

    def _config_return():
        return fake_config

    fake_quilt3 = types.SimpleNamespace(config=_config_return)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    region = quiltx.get_catalog_region()

    assert region == "us-east-1"


def test_get_catalog_region_raises_when_missing(monkeypatch) -> None:
    """Test get_catalog_region raises ValueError when region is missing."""
    fake_config = {"navigator_url": "https://example.test"}

    def _config_return():
        return fake_config

    fake_quilt3 = types.SimpleNamespace(config=_config_return)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    with pytest.raises(ValueError, match="region not found"):
        quiltx.get_catalog_region()


def test_set_catalog_url(monkeypatch) -> None:
    """Test set_catalog_url calls quilt3.config with args."""
    called = {}

    def _config(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs
        return {"navigator_url": args[0] if args else None}

    fake_quilt3 = types.SimpleNamespace(config=_config)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    config = quiltx.set_catalog_url("https://example.test", token="abc123")

    assert called == {
        "args": ("https://example.test",),
        "kwargs": {"token": "abc123"},
    }
    assert config["navigator_url"] == "https://example.test"


def test_set_catalog_url_bare_hostname(monkeypatch) -> None:
    """Test set_catalog_url normalizes bare DNS names to https://."""
    called = {}

    def _config(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs
        return {"navigator_url": args[0] if args else None}

    fake_quilt3 = types.SimpleNamespace(config=_config)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    config = quiltx.set_catalog_url("unstable.dev.quilttest.com")

    assert called["args"] == ("https://unstable.dev.quilttest.com",)
    assert config["navigator_url"] == "https://unstable.dev.quilttest.com"


def test_set_catalog_url_strips_trailing_slash(monkeypatch) -> None:
    """Test set_catalog_url strips trailing slash."""
    called = {}

    def _config(*args, **kwargs):
        called["args"] = args
        return {"navigator_url": args[0] if args else None}

    fake_quilt3 = types.SimpleNamespace(config=_config)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    quiltx.set_catalog_url("https://example.test/")

    assert called["args"] == ("https://example.test",)


def test_auto_login_retries_after_auth_failure(monkeypatch) -> None:
    """Test auto_login catches auth errors, calls quilt3.login(), and retries."""
    call_count = 0
    login_called = False

    @quiltx.auto_login
    def guarded():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("Authentication failed. Check your credentials or API key.")
        return "ok"

    def _fake_login():
        nonlocal login_called
        login_called = True

    fake_quilt3 = types.SimpleNamespace(login=_fake_login)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    result = guarded()

    assert result == "ok"
    assert call_count == 2
    assert login_called


def test_auto_login_does_not_catch_other_errors() -> None:
    """Test auto_login re-raises non-auth errors."""

    @quiltx.auto_login
    def guarded():
        raise ValueError("something else")

    with pytest.raises(ValueError, match="something else"):
        guarded()
