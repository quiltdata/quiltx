"""Tests for `quiltx catalog login`."""

from __future__ import annotations

import pytest

from quiltx import credentials, quilt_auth
from quiltx.tools.catalog import login as login_cmd


def _setup_no_keyring(monkeypatch, tmp_path):
    """Force the file-fallback credentials path into tmp_path."""
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)
    monkeypatch.setattr(credentials, "_fallback_path", lambda: tmp_path / "creds.json")
    monkeypatch.setattr(credentials, "_index_path", lambda: tmp_path / "index.json")
    monkeypatch.setattr(credentials, "_warn_file_fallback", lambda: None)


def test_login_with_api_key_paste_stores_immediately(tmp_path, monkeypatch, capsys):
    _setup_no_keyring(monkeypatch, tmp_path)
    rc = login_cmd.main(
        ["--catalog", "nightly.quilttest.com", "--api-key", "qk_pasted"]
    )
    assert rc == 0
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None and stored["api_key"] == "qk_pasted"


def test_login_rejects_api_key_without_qk_prefix(tmp_path, monkeypatch, capsys):
    _setup_no_keyring(monkeypatch, tmp_path)
    rc = login_cmd.main(
        ["--catalog", "nightly.quilttest.com", "--api-key", "not-a-key"]
    )
    assert rc == 1
    assert "qk_" in capsys.readouterr().err


def test_login_with_username_password_bootstraps(tmp_path, monkeypatch, capsys):
    """Headless U/P -> qk_ via stubbed bootstrap chain."""
    _setup_no_keyring(monkeypatch, tmp_path)

    bootstrap_calls: list[dict] = []

    def fake_bootstrap(catalog_url, *, username, password, name, expires_in_days):
        bootstrap_calls.append(
            {
                "url": catalog_url,
                "user": username,
                "password": password,
                "name": name,
                "expires_in_days": expires_in_days,
            }
        )
        return {
            "secret": "qk_minted",
            "name": name,
            "expires_at": "2027-05-04T00:00:00Z",
        }

    monkeypatch.setattr(quilt_auth, "bootstrap_api_key", fake_bootstrap)

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--password",
            "hunter2",
            "--key-name",
            "ci-key",
            "--expires-in-days",
            "365",
        ]
    )
    assert rc == 0
    assert bootstrap_calls[0]["url"] == "https://nightly.quilttest.com"
    assert bootstrap_calls[0]["user"] == "admin"
    assert bootstrap_calls[0]["expires_in_days"] == 365
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_minted"
    assert stored["name"] == "ci-key"
    # 2027-05-04T00:00:00Z (sanity-check the ISO-8601 parser ran)
    assert stored["expires_at"] == 1809388800


def test_login_no_prompt_without_creds_errors(tmp_path, monkeypatch, capsys):
    _setup_no_keyring(monkeypatch, tmp_path)
    rc = login_cmd.main(["--catalog", "nightly.quilttest.com", "--no-prompt"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--username" in err or "--api-key" in err


def test_login_sso_only_catalog_surfaces_catalog_error(tmp_path, monkeypatch, capsys):
    """When the catalog rejects U/P (SSO-only), the catalog's body is shown
    and the command exits non-zero with a hint to use --api-key."""
    _setup_no_keyring(monkeypatch, tmp_path)

    def fake_bootstrap(*a, **kw):
        raise quilt_auth.CatalogAuthError(
            "Auth request to https://x/api/login failed (401): "
            '{"error": "SSO is required for this catalog"}'
        )

    monkeypatch.setattr(quilt_auth, "bootstrap_api_key", fake_bootstrap)

    with pytest.raises(SystemExit) as excinfo:
        login_cmd.main(
            [
                "--catalog",
                "nightly.quilttest.com",
                "--username",
                "admin",
                "--password",
                "x",
            ]
        )
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "SSO is required" in err
    assert "--api-key" in err  # hint
    assert credentials.get("nightly.quilttest.com") is None  # not stored


def test_login_insecure_localhost_uses_http_url(tmp_path, monkeypatch):
    """--insecure on localhost flips the catalog URL to http://localhost."""
    _setup_no_keyring(monkeypatch, tmp_path)
    captured_url: list[str] = []

    def fake_bootstrap(catalog_url, **kw):
        captured_url.append(catalog_url)
        return {"secret": "qk_local", "name": kw["name"], "expires_at": None}

    monkeypatch.setattr(quilt_auth, "bootstrap_api_key", fake_bootstrap)

    rc = login_cmd.main(
        [
            "--catalog",
            "localhost",
            "--insecure",
            "--username",
            "admin",
            "--password",
            "x",
        ]
    )
    assert rc == 0
    assert captured_url == ["http://localhost"]


def test_login_insecure_rejected_for_non_localhost(tmp_path, monkeypatch, capsys):
    _setup_no_keyring(monkeypatch, tmp_path)
    rc = login_cmd.main(
        [
            "--catalog",
            "example.com",
            "--insecure",
            "--username",
            "admin",
            "--password",
            "x",
        ]
    )
    assert rc == 2
    assert "localhost" in capsys.readouterr().err
