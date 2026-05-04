"""Tests for the U/P -> qk_ API-key bootstrap chain."""

from __future__ import annotations

import json
from typing import Any

import pytest

from quiltx import quilt_auth


def _make_post_json_stub(
    routes: dict[str, Any],
) -> tuple[Any, list[dict[str, Any]]]:
    """Return (stub, calls) where stub honours ``routes`` keyed by URL.

    Each route value is either:
      - a dict response, returned as-is, or
      - an Exception, raised when the URL is POSTed to.
    """
    calls: list[dict[str, Any]] = []

    def stub(url: str, payload: dict[str, Any], *, bearer: str | None = None):
        calls.append({"url": url, "payload": payload, "bearer": bearer})
        if url not in routes:
            raise AssertionError(f"unexpected POST to {url}")
        result = routes[url]
        if isinstance(result, Exception):
            raise result
        return result

    return stub, calls


def test_acquire_refresh_token_happy(monkeypatch) -> None:
    stub, calls = _make_post_json_stub(
        {"https://catalog.example.com/api/login": {"refresh_token": "rt-abc"}}
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    rt = quilt_auth.acquire_refresh_token(
        "https://catalog.example.com", "admin", "hunter2"
    )
    assert rt == "rt-abc"
    assert calls[0]["payload"] == {"username": "admin", "password": "hunter2"}


def test_acquire_refresh_token_missing_token_raises(monkeypatch) -> None:
    stub, _ = _make_post_json_stub(
        {"https://catalog.example.com/api/login": {"foo": "bar"}}
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    with pytest.raises(quilt_auth.CatalogAuthError, match="No refresh_token"):
        quilt_auth.acquire_refresh_token(
            "https://catalog.example.com", "admin", "hunter2"
        )


def test_acquire_refresh_token_sso_error_propagates(monkeypatch) -> None:
    """SSO-only catalog rejects /api/login; surface its body to the caller."""
    sso_err = quilt_auth.CatalogAuthError(
        "Auth request to https://catalog.example.com/api/login failed (401): "
        '{"error": "SSO login required"}'
    )
    stub, _ = _make_post_json_stub({"https://catalog.example.com/api/login": sso_err})
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    with pytest.raises(quilt_auth.CatalogAuthError, match="SSO login required"):
        quilt_auth.acquire_refresh_token(
            "https://catalog.example.com", "admin", "hunter2"
        )


def test_exchange_refresh_token_for_access_token(monkeypatch) -> None:
    stub, calls = _make_post_json_stub(
        {"https://catalog.example.com/api/token": {"access_token": "at-xyz"}}
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    at = quilt_auth.exchange_refresh_token_for_access_token(
        "https://catalog.example.com", "rt-abc"
    )
    assert at == "at-xyz"
    assert calls[0]["payload"] == {"refresh_token": "rt-abc"}


def test_create_api_key_happy(monkeypatch) -> None:
    stub, calls = _make_post_json_stub(
        {
            "https://catalog.example.com/graphql": {
                "data": {
                    "apiKeyCreate": {
                        "__typename": "APIKeyCreated",
                        "apiKey": {
                            "id": "ak-1",
                            "name": "quiltx-host-20260504",
                            "expiresAt": "2027-05-04T00:00:00Z",
                        },
                        "secret": "qk_thesecret",
                    }
                }
            }
        }
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    result = quilt_auth.create_api_key(
        "https://catalog.example.com",
        "at-xyz",
        name="quiltx-host-20260504",
        expires_in_days=365,
    )
    assert result["secret"] == "qk_thesecret"
    assert result["expires_at"] == "2027-05-04T00:00:00Z"
    # GraphQL: bearer + camelCase variables.
    assert calls[0]["bearer"] == "at-xyz"
    assert calls[0]["payload"]["variables"] == {
        "input": {"name": "quiltx-host-20260504", "expiresInDays": 365}
    }


def test_create_api_key_invalid_input(monkeypatch) -> None:
    stub, _ = _make_post_json_stub(
        {
            "https://catalog.example.com/graphql": {
                "data": {
                    "apiKeyCreate": {
                        "__typename": "InvalidInput",
                        "errors": [{"path": "name", "message": "name in use"}],
                    }
                }
            }
        }
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    with pytest.raises(quilt_auth.CatalogAuthError, match="rejected apiKeyCreate"):
        quilt_auth.create_api_key(
            "https://catalog.example.com", "at", name="dup", expires_in_days=90
        )


def test_create_api_key_graphql_top_level_errors(monkeypatch) -> None:
    stub, _ = _make_post_json_stub(
        {
            "https://catalog.example.com/graphql": {
                "errors": [{"message": "Unauthorized"}]
            }
        }
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    with pytest.raises(quilt_auth.CatalogAuthError, match="GraphQL errors"):
        quilt_auth.create_api_key(
            "https://catalog.example.com", "at", name="x", expires_in_days=90
        )


def test_bootstrap_api_key_full_chain(monkeypatch) -> None:
    """End-to-end: U/P -> refresh -> access -> qk_ secret."""
    stub, calls = _make_post_json_stub(
        {
            "https://catalog.example.com/api/login": {"refresh_token": "rt"},
            "https://catalog.example.com/api/token": {"access_token": "at"},
            "https://catalog.example.com/graphql": {
                "data": {
                    "apiKeyCreate": {
                        "__typename": "APIKeyCreated",
                        "apiKey": {
                            "id": "ak",
                            "name": "quiltx-host",
                            "expiresAt": "2027-05-04T00:00:00Z",
                        },
                        "secret": "qk_realdeal",
                    }
                }
            },
        }
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    out = quilt_auth.bootstrap_api_key(
        "https://catalog.example.com",
        username="admin",
        password="hunter2",
        name="quiltx-host",
        expires_in_days=365,
    )
    assert out["secret"] == "qk_realdeal"
    # Hits the three endpoints in order.
    assert [c["url"].rsplit("/", 1)[-1] for c in calls] == ["login", "token", "graphql"]


def test_bootstrap_api_key_works_against_insecure_localhost(monkeypatch) -> None:
    """--insecure path: catalog_url is http://localhost; chain composes the same."""
    stub, calls = _make_post_json_stub(
        {
            "http://localhost/api/login": {"refresh_token": "rt"},
            "http://localhost/api/token": {"access_token": "at"},
            "http://localhost/graphql": {
                "data": {
                    "apiKeyCreate": {
                        "__typename": "APIKeyCreated",
                        "apiKey": {"id": "ak", "name": "n", "expiresAt": None},
                        "secret": "qk_local",
                    }
                }
            },
        }
    )
    monkeypatch.setattr(quilt_auth, "_post_json", stub)
    out = quilt_auth.bootstrap_api_key(
        "http://localhost",
        username="admin",
        password="hunter2",
        name="n",
        expires_in_days=90,
    )
    assert out["secret"] == "qk_local"
    assert calls[0]["url"].startswith("http://localhost/")
