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


class _FakeCredentials:
    def __init__(self, method: str) -> None:
        self.method = method


class _FakeBotocoreSession:
    def __init__(self, credentials: _FakeCredentials | None, account: str) -> None:
        self._credentials = credentials
        self._account = account

    def get_credentials(self) -> _FakeCredentials | None:
        return self._credentials

    def create_client(self, service: str) -> object:
        assert service == "sts"
        account = self._account

        class _Sts:
            def get_caller_identity(self) -> dict[str, str]:
                return {"Account": account}

        return _Sts()


class _FakeHttpResponse:
    def __init__(self, payload: dict[str, str]) -> None:
        self._payload = payload

    def json(self) -> dict[str, str]:
        return self._payload


def _install_fake_quilt3_session(
    monkeypatch,
    *,
    credentials_payload: dict[str, str] | None,
    resolved_method: str | None,
    registry_url: str = "https://registry.example.com",
    account: str = "123456789012",
) -> dict[str, object]:
    """Install a fake quilt3.session; return a dict recording facade calls."""
    calls: dict[str, object] = {}

    fake_session = ModuleType("quilt3.session")

    def get_registry_url() -> str:
        return registry_url

    def get_session() -> object:
        class _Http:
            def get(self, url: str) -> _FakeHttpResponse:
                calls["url"] = url
                if credentials_payload is None:
                    raise RuntimeError("Authentication failed")
                return _FakeHttpResponse(credentials_payload)

        return _Http()

    def create_botocore_session(*, credentials=None):
        calls["credentials"] = credentials
        resolved = (
            _FakeCredentials(resolved_method) if resolved_method is not None else None
        )
        return _FakeBotocoreSession(resolved, account)

    fake_session.get_registry_url = get_registry_url  # type: ignore[attr-defined]
    fake_session.get_session = get_session  # type: ignore[attr-defined]
    fake_session.create_botocore_session = create_botocore_session  # type: ignore[attr-defined]

    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session)
    return calls


_STS_PAYLOAD = {
    "AccessKeyId": "ASIA",
    "SecretAccessKey": "secret",
    "SessionToken": "token",
    "Expiration": "2030-01-01T00:00:00Z",
}


def test_catalog_sts_account_id_uses_registry_issued_credentials(monkeypatch) -> None:
    calls = _install_fake_quilt3_session(
        monkeypatch,
        credentials_payload=_STS_PAYLOAD,
        resolved_method=quilt3_facade.QUILT_CREDENTIALS_METHOD,
    )

    assert quilt3_facade.catalog_sts_account_id() == "123456789012"
    assert calls["url"] == "https://registry.example.com/api/auth/get_credentials"
    assert calls["credentials"] == {
        "access_key": "ASIA",
        "secret_key": "secret",
        "token": "token",
        "expiry_time": "2030-01-01T00:00:00Z",
    }


def test_catalog_sts_account_id_rejects_ambient_credentials(monkeypatch) -> None:
    """Issue #91: ambient AWS credentials must not be reported as the catalog's."""
    import pytest

    _install_fake_quilt3_session(
        monkeypatch,
        credentials_payload=_STS_PAYLOAD,
        resolved_method="shared-credentials-file",
    )

    with pytest.raises(
        quilt3_facade.CatalogCredentialsError, match="shared-credentials-file"
    ):
        quilt3_facade.catalog_sts_account_id()


def test_catalog_sts_account_id_fails_when_registry_mints_nothing(monkeypatch) -> None:
    import pytest

    _install_fake_quilt3_session(
        monkeypatch,
        credentials_payload=None,
        resolved_method=quilt3_facade.QUILT_CREDENTIALS_METHOD,
    )

    with pytest.raises(
        quilt3_facade.CatalogCredentialsError, match="did not issue credentials"
    ):
        quilt3_facade.catalog_sts_account_id()


def test_catalog_sts_account_id_fails_on_incomplete_credentials(monkeypatch) -> None:
    import pytest

    _install_fake_quilt3_session(
        monkeypatch,
        credentials_payload={"AccessKeyId": "ASIA"},
        resolved_method=quilt3_facade.QUILT_CREDENTIALS_METHOD,
    )

    with pytest.raises(
        quilt3_facade.CatalogCredentialsError, match="no usable credentials"
    ):
        quilt3_facade.catalog_sts_account_id()
