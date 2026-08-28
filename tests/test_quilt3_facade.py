"""Tests for the quilt3_facade boundary."""

from __future__ import annotations

import sys
from types import ModuleType

from quiltx import quilt3_facade


def test_login_with_api_key_calls_quilt3_session(monkeypatch) -> None:
    captured: dict[str, str] = {}

    fake_session = ModuleType("quilt3.session")

    def fake_login_with_api_key(key: str, *, registry_url: str) -> None:
        captured["key"] = key
        captured["registry_url"] = registry_url

    fake_session.login_with_api_key = fake_login_with_api_key  # type: ignore[attr-defined]

    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session)
    monkeypatch.setattr(
        quilt3_facade,
        "_resolve_registry_for_active_catalog",
        lambda _catalog_url: "https://registry.example.com",
    )

    quilt3_facade.login_with_api_key("qk_test_value", "https://catalog.example.com")

    assert captured == {
        "key": "qk_test_value",
        "registry_url": "https://registry.example.com",
    }


def test_login_with_api_key_propagates_quilt3_errors(monkeypatch) -> None:
    fake_session = ModuleType("quilt3.session")

    def fake_login_with_api_key(_key: str, *, registry_url: str) -> None:
        assert registry_url == "https://registry.example.com"
        raise ValueError("invalid api key prefix")

    fake_session.login_with_api_key = fake_login_with_api_key  # type: ignore[attr-defined]
    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session)
    monkeypatch.setattr(
        quilt3_facade,
        "_resolve_registry_for_active_catalog",
        lambda _catalog_url: "https://registry.example.com",
    )

    import pytest

    with pytest.raises(ValueError, match="invalid api key prefix"):
        quilt3_facade.login_with_api_key(
            "not-a-real-key", "https://catalog.example.com"
        )


def test_catalog_binding_uses_quilt3_registry_resolver(monkeypatch) -> None:
    calls: dict[str, object] = {}
    token = object()
    fake_session = ModuleType("quilt3.session")

    def set_registry_url_resolver(resolver):
        calls["registry_url"] = resolver()
        return token

    def reset_registry_url_resolver(received_token) -> None:
        calls["reset_token"] = received_token

    fake_session.set_registry_url_resolver = set_registry_url_resolver  # type: ignore[attr-defined]
    fake_session.reset_registry_url_resolver = reset_registry_url_resolver  # type: ignore[attr-defined]
    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session)
    monkeypatch.setattr(
        quilt3_facade,
        "_resolve_registry_for_active_catalog",
        lambda _catalog_url: "https://registry.example.com",
    )

    received_token = quilt3_facade.bind_active_catalog("https://catalog.example.com")
    quilt3_facade.reset_active_catalog(received_token)

    assert received_token is token
    assert calls == {
        "registry_url": "https://registry.example.com",
        "reset_token": token,
    }


def test_published_quilt3_apis_isolate_catalog_api_keys(monkeypatch) -> None:
    import quilt3.session

    catalog_a = "https://catalog-a.example.com"
    catalog_b = "https://catalog-b.example.com"
    registry_a = "https://registry-a.example.com"
    registry_b = "https://registry-b.example.com"
    registries = {catalog_a: registry_a, catalog_b: registry_b}
    monkeypatch.setattr(
        quilt3_facade,
        "_resolve_registry_for_active_catalog",
        registries.__getitem__,
    )

    quilt3.session.clear_api_key()
    token_a = quilt3_facade.bind_active_catalog(catalog_a)
    try:
        quilt3_facade.login_with_api_key("qk_catalog_a", catalog_a)
        session_a = quilt3.session.get_session()

        token_b = quilt3_facade.bind_active_catalog(catalog_b)
        try:
            quilt3_facade.login_with_api_key("qk_catalog_b", catalog_b)
            session_b = quilt3.session.get_session()
        finally:
            quilt3_facade.reset_active_catalog(token_b)

        assert quilt3.session.get_registry_url() == registry_a
        assert session_a.headers["Authorization"] == "Bearer qk_catalog_a"
        assert session_b.headers["Authorization"] == "Bearer qk_catalog_b"
    finally:
        quilt3_facade.reset_active_catalog(token_a)
        quilt3.session.clear_api_key()


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


def test_admin_graphql_returns_the_data_payload(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    class _FakeClient:
        def execute(self, query: str, variables: dict[str, object]):
            calls.append({"query": query, "variables": variables})
            return "raw-response"

        def get_data(self, response: object) -> dict[str, object]:
            assert response == "raw-response"
            return {"bucketConfig": {"name": "bucket-a"}}

    monkeypatch.setattr(quilt3_facade, "admin_graphql_client", lambda: _FakeClient())

    data = quilt3_facade.admin_graphql("query Q($name: String!) { x }", {"name": "b"})

    assert data == {"bucketConfig": {"name": "bucket-a"}}
    assert calls == [
        {"query": "query Q($name: String!) { x }", "variables": {"name": "b"}}
    ]
