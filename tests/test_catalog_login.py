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


def test_api_key_command_prints_stored_secret_without_auth_flow(
    tmp_path, monkeypatch, capsys
):
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.store(
        "nightly.quilttest.com",
        "qk_stored",
        name="stored",
        expires_at=None,
    )

    opened: list[str] = []
    monkeypatch.setattr(
        api_key_cmd.login_cmd.quilt_auth,
        "open_browser",
        lambda url: opened.append(url) or True,
    )

    rc = api_key_cmd.main(["--catalog", "nightly.quilttest.com"])

    assert rc == 0
    assert capsys.readouterr().out == "qk_stored\n"
    assert opened == []


def test_api_key_command_mints_stores_and_prints_new_secret(
    tmp_path, monkeypatch, capsys
):
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

    rc = api_key_cmd.main(["--catalog", "nightly.quilttest.com", "--new"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "qk_printed" in out
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_printed"


def test_api_key_command_mints_when_no_stored_secret(tmp_path, monkeypatch, capsys):
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
            "secret": "qk_first",
            "name": name,
            "expires_at": "2027-05-04T00:00:00Z",
        }

    monkeypatch.setattr(
        quilt_auth, "bootstrap_api_key_from_refresh_token", fake_bootstrap
    )

    rc = api_key_cmd.main(["--catalog", "nightly.quilttest.com"])

    assert rc == 0
    assert "qk_first" in capsys.readouterr().out
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_first"


def test_api_key_command_no_prompt_errors_without_stored_secret(
    tmp_path, monkeypatch, capsys
):
    _setup_no_keyring(monkeypatch, tmp_path)

    rc = api_key_cmd.main(["--catalog", "nightly.quilttest.com", "--no-prompt"])

    assert rc == 1
    assert "no stored API key" in capsys.readouterr().err


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


def test_login_uses_env_password_without_storing(monkeypatch, capsys):
    """CI can mint a key without exposing argv or touching credential storage."""
    bootstrap_calls: list[dict] = []

    def fake_bootstrap(catalog_url, *, username, password, name, expires_in_days):
        bootstrap_calls.append({"username": username, "password": password})
        return {
            "secret": "qk_ephemeral",
            "name": name,
            "expires_at": "2027-05-04T00:00:00Z",
        }

    monkeypatch.setenv("QUILTX_PASSWORD", "env-secret")
    monkeypatch.setattr(quilt_auth, "bootstrap_api_key", fake_bootstrap)
    monkeypatch.setattr(
        credentials,
        "store",
        lambda *_a, **_kw: pytest.fail("--no-store touched credential storage"),
    )

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--no-prompt",
            "--no-store",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert bootstrap_calls == [{"username": "admin", "password": "env-secret"}]
    assert captured.out == "qk_ephemeral\n"
    assert "not stored" in captured.err
    assert "qk_ephemeral" not in captured.err


def test_login_password_stdin_overrides_environment(monkeypatch, capsys):
    from io import StringIO

    received_passwords: list[str] = []

    def fake_bootstrap(catalog_url, *, username, password, name, expires_in_days):
        received_passwords.append(password)
        return {"secret": "qk_stdin", "name": name, "expires_at": None}

    monkeypatch.setenv("QUILTX_PASSWORD", "env-secret")
    monkeypatch.setattr("sys.stdin", StringIO("stdin secret\n"))
    monkeypatch.setattr(quilt_auth, "bootstrap_api_key", fake_bootstrap)

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--password-stdin",
            "--no-store",
        ]
    )

    assert rc == 0
    assert received_passwords == ["stdin secret"]
    assert capsys.readouterr().out == "qk_stdin\n"


def test_login_password_stdin_rejects_empty_input(monkeypatch, capsys):
    from io import StringIO

    monkeypatch.setattr("sys.stdin", StringIO(""))

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--password-stdin",
            "--no-store",
        ]
    )

    assert rc == 2
    assert "No password was provided on stdin" in capsys.readouterr().err


def test_login_password_option_requires_username(capsys):
    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--password-stdin",
            "--no-store",
        ]
    )

    assert rc == 2
    assert "--username is required" in capsys.readouterr().err


def test_login_api_key_no_store_validates_without_persisting(monkeypatch, capsys):
    validated: list[tuple[str, str]] = []
    monkeypatch.setattr(
        quilt_auth,
        "validate_api_key",
        lambda url, key: validated.append((url, key)),
    )
    monkeypatch.setattr(
        credentials,
        "store",
        lambda *_a, **_kw: pytest.fail("--no-store touched credential storage"),
    )

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--api-key",
            "qk_existing",
            "--no-store",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert validated == [("https://nightly.quilttest.com", "qk_existing")]
    assert captured.out == "qk_existing\n"
    assert "not stored" in captured.err


def test_login_rejects_api_key_with_password_option(monkeypatch, capsys):
    monkeypatch.setattr(
        quilt_auth,
        "validate_api_key",
        lambda *_a, **_kw: pytest.fail("conflicting inputs reached validation"),
    )

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--api-key",
            "qk_existing",
            "--password-stdin",
        ]
    )

    assert rc == 2
    assert "cannot be combined" in capsys.readouterr().err


def test_login_password_stdin_announces_interactive_read(monkeypatch, capsys):
    from io import StringIO

    stdin = StringIO("stdin-secret\n")
    monkeypatch.setattr(stdin, "isatty", lambda: True)
    monkeypatch.setattr("sys.stdin", stdin)
    monkeypatch.setattr(
        quilt_auth,
        "bootstrap_api_key",
        lambda catalog_url, **kwargs: {
            "secret": "qk_stdin",
            "name": kwargs["name"],
            "expires_at": None,
        },
    )

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--password-stdin",
            "--no-store",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == "qk_stdin\n"
    assert "Reading password from stdin" in captured.err


def test_login_rejects_empty_env_password(monkeypatch, capsys):
    monkeypatch.setenv("QUILTX_PASSWORD", "")
    monkeypatch.setattr(
        quilt_auth,
        "bootstrap_api_key",
        lambda *_a, **_kw: pytest.fail("empty password reached bootstrap"),
    )

    rc = login_cmd.main(
        [
            "--catalog",
            "nightly.quilttest.com",
            "--username",
            "admin",
            "--no-prompt",
            "--no-store",
        ]
    )

    assert rc == 2
    assert "QUILTX_PASSWORD is set but empty" in capsys.readouterr().err
