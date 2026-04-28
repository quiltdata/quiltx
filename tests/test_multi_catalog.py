"""Tests for Story 3 / Story 5: two Catalog instances in one process."""

from __future__ import annotations

from unittest.mock import patch

import pytest

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
    monkeypatch.delenv("QUILTX_USERNAME", raising=False)
    monkeypatch.delenv("QUILTX_PASSWORD", raising=False)

    dns_a = "cat-a.example.com"
    dns_b = "cat-b.example.com"
    token_a = "refresh-token-for-a"
    token_b = "refresh-token-for-b"

    credentials.store(dns_a, "alice", token_a)
    credentials.store(dns_b, "bob", token_b)

    bound_to: list[str] = []

    def fake_validate(url: str, token: str) -> bool:
        return True

    def fake_set_global_config(url: str, **kw: object) -> None:
        bound_to.append(url)

    def fake_login_with_token(token: str) -> None:
        pass

    cat_a = _make_catalog(dns_a)
    cat_b = _make_catalog(dns_b)

    with (
        patch("quiltx.quilt_auth.validate_refresh_token", fake_validate),
        patch("quiltx.quilt3_facade.set_global_config", fake_set_global_config),
        patch("quiltx.quilt3_facade.login_with_token", fake_login_with_token),
    ):
        cat_a.ensure_auth()
        cat_b.ensure_auth()

    # quilt3 was bound first to cat_a's URL, then to cat_b's URL
    assert "https://cat-a.example.com" in bound_to
    assert "https://cat-b.example.com" in bound_to
    assert bound_to.index("https://cat-a.example.com") < bound_to.index(
        "https://cat-b.example.com"
    )


def test_keyring_entries_dont_cross_contaminate(tmp_path, monkeypatch):
    """Storing credentials for cat_a does not affect cat_b's keyring entry."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)

    credentials.store("cat-a.example.com", "alice", "token-a")
    credentials.store("cat-b.example.com", "bob", "token-b")

    entry_a = credentials.get("cat-a.example.com")
    entry_b = credentials.get("cat-b.example.com")

    assert entry_a is not None and entry_a["username"] == "alice"
    assert entry_b is not None and entry_b["username"] == "bob"


def test_forget_one_does_not_affect_other(tmp_path, monkeypatch):
    """forget cat_a doesn't remove cat_b's credentials."""
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)

    credentials.store("cat-a.example.com", "alice", "token-a")
    credentials.store("cat-b.example.com", "bob", "token-b")

    credentials.delete("cat-a.example.com")

    assert not credentials.has_credentials("cat-a.example.com")
    assert credentials.has_credentials("cat-b.example.com")


# ---------------------------------------------------------------------------
# Story 5: API consumer — Catalog.from_dns
# ---------------------------------------------------------------------------


def test_catalog_from_dns_public_api():
    """Catalog.from_dns is importable from the top-level quiltx package."""
    import quiltx

    assert hasattr(quiltx, "Catalog")
    cat = quiltx.Catalog.from_dns(
        "nightly.quilttest.com", source="flag", auth_required=False
    )
    assert cat.catalog_name == "nightly.quilttest.com"
    assert cat.catalog_url == "https://nightly.quilttest.com"


def test_catalog_from_dns_no_io():
    """Catalog constructor does no I/O."""
    cat = Catalog.from_dns("nightly.quilttest.com", source="flag", auth_required=False)
    assert cat.catalog_name == "nightly.quilttest.com"
    # auth_required=False means ensure_auth is a no-op
    cat.ensure_auth()  # should not raise
