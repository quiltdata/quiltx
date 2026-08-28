"""Tests for Story 3 / Story 5: two Catalog instances in one process."""

from __future__ import annotations

from unittest.mock import patch


from quiltx import credentials
from quiltx.stack import Catalog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _no_keyring(monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)


def _tmp_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)


def _clear_env(monkeypatch):
    monkeypatch.delenv("QUILTX_API_KEY", raising=False)


def _make_catalog(dns: str, *, auth_required: bool = True) -> Catalog:
    return Catalog(
        catalog_name=dns,
        catalog_url=f"https://{dns}",
        source="flag",
        auth_required=auth_required,
    )


# ---------------------------------------------------------------------------
# Order-independence: two catalogs bound sequentially
# ---------------------------------------------------------------------------


def test_two_catalogs_bind_sequentially(tmp_path, monkeypatch):
    """ensure_auth for cat_a then cat_b: each binds quilt3 to its own URL."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    _clear_env(monkeypatch)

    dns_a = "cat-a.example.com"
    dns_b = "cat-b.example.com"

    credentials.store(dns_a, "qk_for_a")
    credentials.store(dns_b, "qk_for_b")

    bound_to: list[str] = []
    keys_used: list[tuple[str, str]] = []

    cat_a = _make_catalog(dns_a)
    cat_b = _make_catalog(dns_b)

    with (
        patch(
            "quiltx.quilt3_facade.bind_active_catalog",
            lambda url: bound_to.append(url) or "TOKEN",
        ),
        patch(
            "quiltx.quilt3_facade.login_with_api_key",
            lambda key, catalog_url: keys_used.append((key, catalog_url)),
        ),
    ):
        cat_a.ensure_auth()
        cat_b.ensure_auth()

    assert bound_to == ["https://cat-a.example.com", "https://cat-b.example.com"]
    assert keys_used == [
        ("qk_for_a", "https://cat-a.example.com"),
        ("qk_for_b", "https://cat-b.example.com"),
    ]


def test_keyring_entries_dont_cross_contaminate(tmp_path, monkeypatch):
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)

    credentials.store("cat-a.example.com", "qk_a")
    credentials.store("cat-b.example.com", "qk_b")

    entry_a = credentials.get("cat-a.example.com")
    entry_b = credentials.get("cat-b.example.com")

    assert entry_a is not None and entry_a["api_key"] == "qk_a"
    assert entry_b is not None and entry_b["api_key"] == "qk_b"


def test_forget_one_does_not_affect_other(tmp_path, monkeypatch):
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)

    credentials.store("cat-a.example.com", "qk_a")
    credentials.store("cat-b.example.com", "qk_b")

    credentials.delete("cat-a.example.com")

    assert not credentials.has_credentials("cat-a.example.com")
    assert credentials.has_credentials("cat-b.example.com")


# ---------------------------------------------------------------------------
# Story 5: API consumer — Catalog.from_dns
# ---------------------------------------------------------------------------


def test_catalog_from_dns_public_api():
    import quiltx

    assert hasattr(quiltx, "Catalog")
    cat = quiltx.Catalog.from_dns(
        "nightly.quilttest.com", source="flag", auth_required=False
    )
    assert cat.catalog_name == "nightly.quilttest.com"
    assert cat.catalog_url == "https://nightly.quilttest.com"


def test_catalog_from_dns_no_io():
    cat = Catalog.from_dns("nightly.quilttest.com", source="flag", auth_required=False)
    assert cat.catalog_name == "nightly.quilttest.com"
    cat.ensure_auth()  # auth_required=False — no-op


def test_catalog_from_dns_api_key_threaded_to_resolver(tmp_path, monkeypatch):
    """api_key passed to from_dns is used as the API-ladder step 1."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    _clear_env(monkeypatch)

    keys_used: list[tuple[str, str]] = []

    cat = Catalog.from_dns("kw.example.com", source="flag", api_key="qk_kw")

    with (
        patch(
            "quiltx.quilt3_facade.bind_active_catalog",
            lambda url: "TOKEN",
        ),
        patch(
            "quiltx.quilt3_facade.login_with_api_key",
            lambda key, catalog_url: keys_used.append((key, catalog_url)),
        ),
    ):
        cat.ensure_auth()

    assert keys_used == [("qk_kw", "https://kw.example.com")]
