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
