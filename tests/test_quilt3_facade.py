"""Tests for the quilt3_facade boundary."""

from __future__ import annotations

import sys
from types import ModuleType

from quiltx import quilt3_facade


def test_login_with_api_key_calls_quilt3_session(monkeypatch) -> None:
    captured: dict[str, str] = {}

    fake_session = ModuleType("quilt3.session")

    def fake_login_with_api_key(key: str) -> None:
        captured["key"] = key

    fake_session.login_with_api_key = fake_login_with_api_key  # type: ignore[attr-defined]

    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session)

    quilt3_facade.login_with_api_key("qk_test_value")

    assert captured == {"key": "qk_test_value"}


def test_login_with_api_key_propagates_quilt3_errors(monkeypatch) -> None:
    fake_session = ModuleType("quilt3.session")

    def fake_login_with_api_key(_key: str) -> None:
        raise ValueError("invalid api key prefix")

    fake_session.login_with_api_key = fake_login_with_api_key  # type: ignore[attr-defined]
    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session)

    import pytest

    with pytest.raises(ValueError, match="invalid api key prefix"):
        quilt3_facade.login_with_api_key("not-a-real-key")
