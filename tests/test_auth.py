"""Tests for quiltx.auth API-key resolver."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from quiltx import auth
from quiltx.auth import store as credentials
from quiltx.stack import Catalog

FAKE_CATALOG = Catalog(
    catalog_name="nightly.quilttest.com",
    catalog_url="https://nightly.quilttest.com",
    source="flag",
)


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
    monkeypatch.delenv("QUILTX_NO_PROMPT", raising=False)


# ---------------------------------------------------------------------------
# CLI ladder
# ---------------------------------------------------------------------------


def test_cli_flag(monkeypatch):
    """--api-key flag is top priority."""
    _clear_env(monkeypatch)
    args = SimpleNamespace(api_key="qk_flag", no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_flag"
    assert result.source == "flag"


def test_cli_env_var(monkeypatch):
    """QUILTX_API_KEY is used when no flag."""
    monkeypatch.setenv("QUILTX_API_KEY", "qk_env")
    args = SimpleNamespace(api_key=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_env"
    assert result.source == "env"


def test_cli_no_creds_raises_in_headless(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError, match="No API key available"):
        auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_keyring(monkeypatch, tmp_path):
    """Keyring entry is found at step 3."""
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_keyring")
    args = SimpleNamespace(api_key=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_keyring"
    assert result.source == "keyring"


def test_cli_skip_keyring(monkeypatch, tmp_path):
    """skip_keyring=True forces fallthrough to prompt/env even with stored entry."""
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_keyring")
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError, match="No API key available"):
        auth.resolve_cli(FAKE_CATALOG, args, skip_keyring=True)


def test_cli_auth_flow_mints_and_stores_key(monkeypatch, tmp_path):
    """Interactive auth flow mints and stores an API key."""
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=False)

    from quiltx.tools.catalog import login as login_tool

    def fake_mint(catalog_url, dns, **_kw):
        assert catalog_url == "https://nightly.quilttest.com"
        assert dns == "nightly.quilttest.com"
        credentials.store(dns, "qk_minted", name="minted", expires_at=None)
        return login_tool.MintedApiKey(
            secret="qk_minted", name="minted", expires_at=None
        )

    monkeypatch.setattr(login_tool, "mint_api_key", fake_mint)

    with (patch("sys.stdin.isatty", return_value=True),):
        result = auth.resolve_cli(FAKE_CATALOG, args)

    assert result.api_key == "qk_minted"
    assert result.source == "auth-flow"
    stored = credentials.get("nightly.quilttest.com")
    assert stored is not None
    assert stored["api_key"] == "qk_minted"
    assert stored.get("name") == "minted"
    assert stored.get("expires_at") is None


def test_cli_auth_flow_error_propagates(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=False)

    from quiltx.tools.catalog import login as login_tool

    def fake_mint(*_a, **_kw):
        raise login_tool.LoginError("No code provided.")

    monkeypatch.setattr(login_tool, "mint_api_key", fake_mint)

    with (patch("sys.stdin.isatty", return_value=True),):
        with pytest.raises(auth.CredentialError, match="No code provided"):
            auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_no_prompt_flag_blocks_interactive(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError):
        auth.resolve_cli(FAKE_CATALOG, args)


def test_cli_quiltx_no_prompt_env(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    monkeypatch.setenv("QUILTX_NO_PROMPT", "1")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    args = SimpleNamespace(api_key=None, no_prompt=False)
    with pytest.raises(auth.CredentialError):
        auth.resolve_cli(FAKE_CATALOG, args)


# ---------------------------------------------------------------------------
# API ladder
# ---------------------------------------------------------------------------


def test_api_env_var(monkeypatch):
    monkeypatch.setenv("QUILTX_API_KEY", "qk_api_env")
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.api_key == "qk_api_env"
    assert result.source == "env"


def test_api_keyring(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_api_kring")
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.api_key == "qk_api_kring"
    assert result.source == "keyring"


def test_api_no_prompt_raises(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    with pytest.raises(auth.CredentialError):
        auth.resolve_api(FAKE_CATALOG)


def test_api_kwarg_takes_priority(monkeypatch, tmp_path):
    monkeypatch.setenv("QUILTX_API_KEY", "qk_env")
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_stored")

    result = auth.resolve_api(FAKE_CATALOG, api_key="qk_kw")
    assert result.api_key == "qk_kw"
    assert result.source == "flag"


def test_api_skip_keyring(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    _no_keyring(monkeypatch)
    _tmp_fallback(monkeypatch, tmp_path)
    credentials.set("nightly.quilttest.com", "qk_stored")
    with pytest.raises(auth.CredentialError):
        auth.resolve_api(FAKE_CATALOG, skip_keyring=True)


# ---------------------------------------------------------------------------
# Wrapper short-circuits (store and isatty must not run on a flag/env hit)
# ---------------------------------------------------------------------------


def _raising_get(monkeypatch, exc: BaseException):
    calls: list[str] = []

    def get(dns: str):
        calls.append(dns)
        raise exc

    monkeypatch.setattr(credentials, "get", get)
    return calls


def test_cli_flag_does_not_call_the_store_even_when_get_raises(monkeypatch) -> None:
    _clear_env(monkeypatch)
    calls = _raising_get(monkeypatch, ValueError("store should not be called"))
    args = SimpleNamespace(api_key="qk_flag", no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_flag"
    assert result.source == "flag"
    assert calls == []


def test_cli_env_does_not_call_the_store_even_when_get_raises(monkeypatch) -> None:
    monkeypatch.setenv("QUILTX_API_KEY", "qk_env")
    calls = _raising_get(monkeypatch, OSError("store should not be called"))
    args = SimpleNamespace(api_key=None, no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_env"
    assert result.source == "env"
    assert calls == []


def test_api_kwarg_does_not_call_the_store_even_when_get_raises(monkeypatch) -> None:
    _clear_env(monkeypatch)
    from keyring.errors import KeyringLocked

    calls = _raising_get(monkeypatch, KeyringLocked("store should not be called"))
    result = auth.resolve_api(FAKE_CATALOG, api_key="qk_kw")
    assert result.api_key == "qk_kw"
    assert result.source == "flag"
    assert calls == []


def test_api_env_does_not_call_the_store_even_when_get_raises(monkeypatch) -> None:
    monkeypatch.setenv("QUILTX_API_KEY", "qk_api_env")
    from keyring.errors import NoKeyringError

    calls = _raising_get(monkeypatch, NoKeyringError("store should not be called"))
    result = auth.resolve_api(FAKE_CATALOG)
    assert result.api_key == "qk_api_env"
    assert result.source == "env"
    assert calls == []


def test_cli_flag_succeeds_when_stdin_is_closed(monkeypatch) -> None:
    _clear_env(monkeypatch)
    closed = __import__("io").StringIO()
    closed.close()
    monkeypatch.setattr("sys.stdin", closed)
    # A store error would also fire if we read eagerly; keep get clean
    # so a regression is clearly an isatty failure.
    args = SimpleNamespace(api_key="qk_flag", no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_flag"
    assert result.source == "flag"


def test_cli_flag_succeeds_when_stdin_is_none(monkeypatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setattr("sys.stdin", None)
    args = SimpleNamespace(api_key="qk_flag", no_prompt=False)
    result = auth.resolve_cli(FAKE_CATALOG, args)
    assert result.api_key == "qk_flag"
    assert result.source == "flag"


def test_api_kwarg_non_string_passes_through(monkeypatch) -> None:
    """A truthy non-string api_key= is returned as-is, as the old wrapper did."""
    _clear_env(monkeypatch)
    calls = _raising_get(monkeypatch, ValueError("store should not be called"))
    result = auth.resolve_api(FAKE_CATALOG, api_key=b"qk_bytes")  # type: ignore[arg-type]
    assert result.api_key == b"qk_bytes"
    assert result.source == "flag"
    assert calls == []
    result = auth.resolve_api(FAKE_CATALOG, api_key=1)  # type: ignore[arg-type]
    assert result.api_key == 1
    assert result.source == "flag"
    assert calls == []


def test_stored_null_api_key_falls_through(monkeypatch) -> None:
    """A stored api_key of null is a miss, not (None, "keyring")."""
    _clear_env(monkeypatch)
    monkeypatch.setattr(credentials, "get", lambda dns: {"api_key": None})
    args = SimpleNamespace(api_key=None, no_prompt=True)
    with pytest.raises(auth.CredentialError, match="No API key available"):
        auth.resolve_cli(FAKE_CATALOG, args)
    with pytest.raises(auth.CredentialError, match="No API key available"):
        auth.resolve_api(FAKE_CATALOG)


# ---------------------------------------------------------------------------
# Wrapper parity against the 8723678 resolve.py
# ---------------------------------------------------------------------------


def _wrapper_outcome(fn, *args, **kwargs):
    try:
        got = fn(*args, **kwargs)
        return ("ok", got)
    except Exception as exc:  # type and message are the contract
        return ("error", type(exc), str(exc))


@pytest.mark.parametrize("mode", ["cli", "api"])
@pytest.mark.parametrize("flag", [None, "", "qk_flag", b"qk_flag", 1])
@pytest.mark.parametrize("env", [None, "", "qk_env"])
@pytest.mark.parametrize(
    "store",
    [
        "missing",
        "present",
        "empty_string",
        "null",
        "nonstring",
        "ValueError",
        "OSError",
        "KeyringLocked",
        "NoKeyringError",
        "TypeError",
    ],
)
@pytest.mark.parametrize("tty", [True, False])
@pytest.mark.parametrize("no_prompt", [False, True])
@pytest.mark.parametrize("skip_keyring", [False, True])
def test_resolve_wrappers_match_the_8723678_oracle(
    monkeypatch,
    mode: str,
    flag: object,
    env: str | None,
    store: str,
    tty: bool,
    no_prompt: bool,
    skip_keyring: bool,
) -> None:
    from io import StringIO

    from keyring.errors import KeyringLocked, NoKeyringError
    from quiltx.tools.catalog import login as login_tool

    from tests import oracle_resolve_wrapper as old

    # The one documented difference: a stored api_key of null now falls
    # through instead of returning (None, "keyring").
    if store == "null" and not flag and not env and not skip_keyring:
        pytest.skip("stored api_key: null fall-through is a documented change")

    _clear_env(monkeypatch)
    if env is not None:
        monkeypatch.setenv("QUILTX_API_KEY", env)

    store_payloads = {
        "missing": None,
        "present": {"api_key": "qk_stored"},
        "empty_string": {"api_key": ""},
        "null": {"api_key": None},
        "nonstring": {"api_key": 123},
    }
    store_errors = {
        "ValueError": ValueError("bad store"),
        "OSError": OSError("io"),
        "KeyringLocked": KeyringLocked("locked"),
        "NoKeyringError": NoKeyringError("none"),
        "TypeError": TypeError("non-string key"),
    }

    def install_get() -> list[str]:
        calls: list[str] = []

        def get(dns: str):
            calls.append(dns)
            if store in store_errors:
                raise store_errors[store]
            return store_payloads[store]

        monkeypatch.setattr(credentials, "get", get)
        return calls

    class _Stdin:
        def isatty(self) -> bool:
            return tty

    monkeypatch.setattr("sys.stdin", _Stdin())
    monkeypatch.setattr(
        login_tool,
        "mint_api_key",
        lambda *a, **k: login_tool.MintedApiKey(
            secret="qk_minted", name="minted", expires_at=None
        ),
    )
    monkeypatch.setattr(login_tool, "print_stored_message", lambda *a, **k: None)

    args = SimpleNamespace(api_key=flag, no_prompt=no_prompt)

    new_calls = install_get()
    if mode == "cli":
        new_out = _wrapper_outcome(
            auth.resolve_cli, FAKE_CATALOG, args, skip_keyring=skip_keyring
        )
    else:
        new_out = _wrapper_outcome(
            auth.resolve_api,
            FAKE_CATALOG,
            api_key=flag,
            skip_keyring=skip_keyring,
        )
    new_count = list(new_calls)

    old_calls = install_get()
    if mode == "cli":
        old_out = _wrapper_outcome(
            old.resolve_cli, FAKE_CATALOG, args, skip_keyring=skip_keyring
        )
    else:
        old_out = _wrapper_outcome(
            old.resolve_api,
            FAKE_CATALOG,
            api_key=flag,
            skip_keyring=skip_keyring,
        )
    old_count = list(old_calls)

    assert new_out == old_out, (mode, flag, env, store, tty, no_prompt, skip_keyring)
    assert new_count == old_count, (
        mode,
        flag,
        env,
        store,
        tty,
        no_prompt,
        skip_keyring,
        new_count,
        old_count,
    )


def test_cli_flag_matches_oracle_with_closed_or_none_stdin(monkeypatch) -> None:
    from io import StringIO

    from tests import oracle_resolve_wrapper as old

    _clear_env(monkeypatch)
    args = SimpleNamespace(api_key="qk_flag", no_prompt=False)
    closed = StringIO()
    closed.close()
    for stdin in (closed, None):
        monkeypatch.setattr("sys.stdin", stdin)
        calls: list[str] = []

        def get(dns: str, calls=calls):
            calls.append(dns)
            raise ValueError("store should not be called")

        monkeypatch.setattr(credentials, "get", get)
        new_out = _wrapper_outcome(auth.resolve_cli, FAKE_CATALOG, args)
        old_out = _wrapper_outcome(old.resolve_cli, FAKE_CATALOG, args)
        assert new_out == old_out
        assert new_out == ("ok", auth.ResolvedCredentials("qk_flag", "flag"))
        assert calls == []
