"""Tests for quiltx.credentials (keyring-backed + file fallback)."""

from __future__ import annotations

from unittest.mock import patch


from quiltx import credentials


def _mock_no_keyring(monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)


def _use_tmp_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)


# ---------------------------------------------------------------------------
# File-fallback tests (no keyring backend)
# ---------------------------------------------------------------------------


def test_file_fallback_get_none_when_missing(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)
    assert credentials.get("nightly.quilttest.com") is None


def test_file_fallback_set_and_get(tmp_path, monkeypatch, capsys):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("nightly.quilttest.com", "qk_test_value")
    result = credentials.get("nightly.quilttest.com")
    assert result is not None
    assert result["api_key"] == "qk_test_value"
    # Paste-only bootstrap leaves metadata null
    assert result.get("name") is None
    assert result.get("expires_at") is None

    # Warning should have been printed
    captured = capsys.readouterr()
    assert "WARNING" in captured.err


def test_file_fallback_set_with_metadata(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set(
        "nightly.quilttest.com",
        "qk_named",
        name="ci-runner",
        expires_at=1_800_000_000,
    )
    result = credentials.get("nightly.quilttest.com")
    assert result is not None
    assert result["api_key"] == "qk_named"
    assert result["name"] == "ci-runner"
    assert result["expires_at"] == 1_800_000_000


def test_file_fallback_delete_idempotent(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("nightly.quilttest.com", "qk_value")
    credentials.delete("nightly.quilttest.com")
    assert credentials.get("nightly.quilttest.com") is None
    credentials.delete("nightly.quilttest.com")  # idempotent


def test_file_fallback_has_credentials(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    assert not credentials.has_credentials("nightly.quilttest.com")
    credentials.set("nightly.quilttest.com", "qk_value")
    assert credentials.has_credentials("nightly.quilttest.com")


def test_file_fallback_list(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("a.example.com", "qk_a", name="alice-key")
    credentials.set("b.example.com", "qk_b")

    entries = credentials.catalog_list()
    dns_list = [e[0] for e in entries]
    assert "a.example.com" in dns_list
    assert "b.example.com" in dns_list
    # Entries carry full metadata
    by_dns = dict(entries)
    assert by_dns["a.example.com"]["api_key"] == "qk_a"
    assert by_dns["a.example.com"]["name"] == "alice-key"


def test_public_aliases_match_internal_names():
    assert credentials.set is credentials.store
    assert credentials.list is credentials.catalog_list


def test_file_mode_600(tmp_path, monkeypatch):
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    credentials.set("nightly.quilttest.com", "qk_value")
    cred_file = tmp_path / "credentials.json"
    assert cred_file.exists()
    mode = oct(cred_file.stat().st_mode)
    assert mode.endswith("600"), f"Expected 0600 mode, got {mode}"


def test_legacy_username_secret_entry_ignored(tmp_path, monkeypatch):
    """Old {username, secret} entries are not surfaced as API-key entries."""
    _mock_no_keyring(monkeypatch)
    _use_tmp_fallback(monkeypatch, tmp_path)

    import json

    path = tmp_path / "credentials.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"old.example.com": {"username": "u", "secret": "s"}}))

    assert credentials.get("old.example.com") is None
    assert not credentials.has_credentials("old.example.com")
    assert credentials.catalog_list() == []


# ---------------------------------------------------------------------------
# Index-backed list (keyring path)
# ---------------------------------------------------------------------------


def test_keyring_list_via_index(tmp_path, monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_available", lambda: True)
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )

    stored: dict[str, str] = {}

    def fake_get_password(service, key):
        return stored.get(key)

    def fake_set_password(service, key, value):
        stored[key] = value

    def fake_delete_password(service, key):
        stored.pop(key, None)

    with (
        patch("keyring.get_password", fake_get_password),
        patch("keyring.set_password", fake_set_password),
        patch("keyring.delete_password", fake_delete_password),
    ):
        credentials.set("x.example.com", "qk_x")
        entries = credentials.catalog_list()
        assert any(e[0] == "x.example.com" for e in entries)

        credentials.delete("x.example.com")
        entries = credentials.catalog_list()
        assert not any(e[0] == "x.example.com" for e in entries)
