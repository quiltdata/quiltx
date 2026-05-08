"""Tests for `quiltx catalog login`."""

from __future__ import annotations

import pytest

from quiltx import credentials, quilt_auth
from quiltx.tools.catalog import api_key as api_key_cmd
from quiltx.tools.catalog import login as login_cmd


def _setup_no_keyring(monkeypatch, tmp_path):
    """Force the file-fallback credentials path into tmp_path."""
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)
    monkeypatch.setattr(credentials, "_fallback_path", lambda: tmp_path / "creds.json")
    monkeypatch.setattr(credentials, "_index_path", lambda: tmp_path / "index.json")
    monkeypatch.setattr(credentials, "_warn_file_fallback", lambda: None)


def test_login_with_api_key_paste_validates_and_stores(tmp_path, monkeypatch, capsys):
    _setup_no_keyring(monkeypatch, tmp_path)
    validate_calls: list[tuple[str, str]] = []

    def fake_validate(catalog_url, api_key):
        validate_calls.append((catalog_url, api_key))

    monkeypatch.setattr(quilt_auth, "validate_api_key", fake_validate)

    rc = login_cmd.main(
        ["--catalog", "nightly.quilttest.com", "--api-key", "qk_pasted"]
    )
    assert rc == 0
    assert validate_calls == [("https://nightly.quilttest.com", "qk_pasted")]
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None and stored["api_key"] == "qk_pasted"


def test_login_with_api_key_paste_rejected_by_catalog(tmp_path, monkeypatch, capsys):
    """Bad paste: catalog rejects the key. Don't store it; error non-zero."""
    _setup_no_keyring(monkeypatch, tmp_path)

    def fake_validate(catalog_url, api_key):
        raise quilt_auth.CatalogAuthError("Catalog rejected API key: 401")

    monkeypatch.setattr(quilt_auth, "validate_api_key", fake_validate)

    rc = login_cmd.main(["--catalog", "nightly.quilttest.com", "--api-key", "qk_bogus"])
    assert rc == 1
    assert "rejected" in capsys.readouterr().err
    assert credentials.get("nightly.quilttest.com") is None


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
    assert "--username" in err and "interactive TTY" in err


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

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--password",
            "x",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "SSO is required" in err
    assert "browser auth flow" in err
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


def test_login_browser_flow_default_on_tty(tmp_path, monkeypatch, capsys):
    """No --username, no --api-key, on a TTY: open browser and accept paste."""
    _setup_no_keyring(monkeypatch, tmp_path)

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    opened: list[str] = []
    monkeypatch.setattr(
        login_cmd.quilt_auth,
        "open_browser",
        lambda url: opened.append(url) or True,
    )
    monkeypatch.setattr(
        login_cmd.quilt_auth,
        "browser_login_url",
        lambda _catalog_url: "https://nightly.quilttest.com/login",
    )
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "rt_pasted")

    bootstrap_calls: list[dict] = []

    def fake_bootstrap(catalog_url, *, refresh_token, name, expires_in_days):
        bootstrap_calls.append(
            {
                "url": catalog_url,
                "refresh_token": refresh_token,
                "name": name,
                "expires_in_days": expires_in_days,
            }
        )
        return {
            "secret": "qk_browser",
            "name": name,
            "expires_at": "2027-05-04T00:00:00Z",
        }

    monkeypatch.setattr(
        quilt_auth, "bootstrap_api_key_from_refresh_token", fake_bootstrap
    )

    rc = login_cmd.main(["--catalog", "nightly.quilttest.com"])
    assert rc == 0
    assert opened == ["https://nightly.quilttest.com/login"]
    assert bootstrap_calls[0]["refresh_token"] == "rt_pasted"
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_browser"


def test_api_key_command_mints_stores_and_prints_secret(tmp_path, monkeypatch, capsys):
    _setup_no_keyring(monkeypatch, tmp_path)

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        api_key_cmd.login_cmd.quilt_auth,
        "open_browser",
        lambda _url: True,
    )
    monkeypatch.setattr(
        api_key_cmd.login_cmd.quilt_auth,
        "browser_login_url",
        lambda _catalog_url: "https://nightly.quilttest.com/login",
    )
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "rt_pasted")

    def fake_bootstrap(catalog_url, *, refresh_token, name, expires_in_days):
        assert catalog_url == "https://nightly.quilttest.com"
        assert refresh_token == "rt_pasted"
        return {
            "secret": "qk_printed",
            "name": name,
            "expires_at": "2027-05-04T00:00:00Z",
        }

    monkeypatch.setattr(
        quilt_auth, "bootstrap_api_key_from_refresh_token", fake_bootstrap
    )

    rc = api_key_cmd.main(["--catalog", "nightly.quilttest.com"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "qk_printed" in out
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_printed"


def test_login_no_browser_falls_back_to_username_prompt(tmp_path, monkeypatch, capsys):
    """--no-browser on a TTY without --username: prompt for U/P instead."""
    _setup_no_keyring(monkeypatch, tmp_path)

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    inputs = iter(["admin"])
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: next(inputs))
    monkeypatch.setattr(login_cmd.getpass, "getpass", lambda *_a, **_kw: "hunter2")

    captured: list[dict] = []

    def fake_bootstrap(catalog_url, *, username, password, name, expires_in_days):
        captured.append({"user": username, "password": password})
        return {"secret": "qk_up", "name": name, "expires_at": None}

    monkeypatch.setattr(quilt_auth, "bootstrap_api_key", fake_bootstrap)

    rc = login_cmd.main(["--catalog", "nightly.quilttest.com", "--no-browser"])
    assert rc == 0
    assert captured == [{"user": "admin", "password": "hunter2"}]


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
