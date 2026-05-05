"""Tests for `quiltx catalog list` and `quiltx catalog forget`."""

from __future__ import annotations


from quiltx import credentials, userconfig
from quiltx.tools.catalog import forget as forget_cmd
from quiltx.tools.catalog import list_ as list_cmd


def _setup_no_keyring(monkeypatch, tmp_path):
    """Use file fallback + tmp_path for all credential storage."""
    monkeypatch.setattr(credentials, "_keyring_available", lambda: False)
    monkeypatch.setattr(
        credentials, "_fallback_path", lambda: tmp_path / "credentials.json"
    )
    monkeypatch.setattr(
        credentials, "_index_path", lambda: tmp_path / "credentials_index.json"
    )
    monkeypatch.setattr(credentials, "_FILE_FALLBACK_WARNED", False)
    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")


# ---------------------------------------------------------------------------
# catalog list
# ---------------------------------------------------------------------------


def test_list_empty(tmp_path, monkeypatch, capsys):
    """Empty list shows 'No catalogs known'."""
    _setup_no_keyring(monkeypatch, tmp_path)
    result = list_cmd.main([])
    assert result == 0
    captured = capsys.readouterr()
    assert "No catalogs known" in captured.out


def test_list_shows_entries(tmp_path, monkeypatch, capsys):
    """Stored entries appear in list output without secrets."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("alpha.example.com", "qk_alpha", name="alice-key")
    credentials.set("beta.example.com", "qk_beta")

    result = list_cmd.main([])
    assert result == 0
    captured = capsys.readouterr()
    assert "alpha.example.com" in captured.out
    assert "beta.example.com" in captured.out
    assert "alice-key" in captured.out
    # Beta has no name → renders UNKNOWN per [05 §7]
    assert "UNKNOWN" in captured.out
    # API keys must not appear in output
    assert "qk_alpha" not in captured.out
    assert "qk_beta" not in captured.out


def test_list_never_renders_secret_value(tmp_path, monkeypatch, capsys):
    """Pinning test for spec [05 §7]: no column ever surfaces the secret.

    Uses a distinctive long secret (with the ``qk_`` prefix and tail) plus
    an entry whose name and expires_at exercise every rendered column.
    Asserts no substring of the secret leaks into stdout/stderr — covers
    both the 'qk_' prefix path and the post-prefix payload.
    """
    _setup_no_keyring(monkeypatch, tmp_path)
    secret = "qk_" + "S3CR3T" * 8  # 51 chars, distinctive non-prefix tail
    credentials.set(
        "rendered.example.com",
        secret,
        name="ci-runner",
        expires_at=int(2_000_000_000),  # 2033-05-18, → "ACTIVE"
    )
    credentials.set("expired.example.com", "qk_" + "X" * 32, expires_at=1)
    credentials.set("nameless.example.com", "qk_" + "Y" * 32)

    result = list_cmd.main([])
    assert result == 0
    captured = capsys.readouterr()

    for stream in (captured.out, captured.err):
        # Whole secrets
        assert secret not in stream
        assert "qk_" + "X" * 32 not in stream
        assert "qk_" + "Y" * 32 not in stream
        # Distinctive non-prefix tails (defence-in-depth: even partial leaks fail)
        assert "S3CR3T" not in stream
        assert "X" * 32 not in stream
        assert "Y" * 32 not in stream


# ---------------------------------------------------------------------------
# catalog forget
# ---------------------------------------------------------------------------


def test_forget_removes_entry(tmp_path, monkeypatch, capsys):
    """forget removes the keyring entry and prints confirmation."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_pass")

    result = forget_cmd.main(["nightly.quilttest.com"])
    assert result == 0
    captured = capsys.readouterr()
    assert "Forgot nightly.quilttest.com" in captured.out
    assert not credentials.has_credentials("nightly.quilttest.com")


def test_forget_idempotent(tmp_path, monkeypatch, capsys):
    """Forgetting an unknown catalog is idempotent (no error)."""
    _setup_no_keyring(monkeypatch, tmp_path)
    result = forget_cmd.main(["unknown.example.com"])
    assert result == 0
    captured = capsys.readouterr()
    assert "Forgot unknown.example.com" in captured.out


def test_forget_url_normalised(tmp_path, monkeypatch):
    """Full URL is normalised before deletion."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_pass")

    result = forget_cmd.main(["https://nightly.quilttest.com/"])
    assert result == 0
    assert not credentials.has_credentials("nightly.quilttest.com")


def test_forget_http_rejected(tmp_path, monkeypatch, capsys):
    """http:// identifier is rejected."""
    _setup_no_keyring(monkeypatch, tmp_path)
    result = forget_cmd.main(["http://nightly.quilttest.com"])
    assert result == 1
    captured = capsys.readouterr()
    assert "Error" in captured.err


def test_forget_does_not_touch_default(tmp_path, monkeypatch):
    """Forgetting the default catalog does NOT auto-elect another."""
    _setup_no_keyring(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_pass")
    userconfig.set_default_catalog("nightly.quilttest.com")

    forget_cmd.main(["nightly.quilttest.com"])

    # Default is still pointing at nightly — the spec says forget does not
    # modify the default; the next un-flagged command surfaces the "no creds" error.
    assert userconfig.get_default_catalog() == "nightly.quilttest.com"
