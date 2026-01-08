from __future__ import annotations

import sys
import types

import quiltx


def test_configured_catalog_calls_quilt3_config(monkeypatch) -> None:
    called = {}

    def _config(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs

    class _Config:
        pass

    def _config_return(*args, **kwargs):
        _config(*args, **kwargs)
        return _Config()

    fake_quilt3 = types.SimpleNamespace(config=_config_return)

    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    config = quiltx.configured_catalog("https://example.test", token="abc123")

    assert called == {
        "args": ("https://example.test",),
        "kwargs": {"token": "abc123"},
    }
    assert isinstance(config, _Config)
