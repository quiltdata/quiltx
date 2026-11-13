"""Rust (``quiltx._core``) versus the Python it replaced (``tests/oracle.py``).

Every input runs through both and the outcomes must be equal: the same value,
or the same exception type with the same message. The inputs are a hand-written
table, then a seeded random walk over the characters that matter in a host
(scheme, ``:``, ``/``, ``@``, ``[``, ``%``, digits, case, whitespace). The path
tests set ``XDG_DATA_HOME`` and ``HOME`` to every combination that changes the
answer and compare with ``platformdirs`` itself on the machine running the test,
so each CI platform checks its own branch (Linux glibc, Linux musl, macOS,
Windows).

Where Python's own answer depends on its version, the table says so: those
inputs are compared only on the versions where Python agrees with Rust.
"""

from __future__ import annotations

import random
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

import platformdirs
import pytest

from quiltx import _core
from quiltx.auth import _native, store
from tests import oracle

Outcome = tuple[str, ...]


def outcome(fn: Callable[..., object], *args: object) -> Outcome:
    try:
        return ("ok", str(fn(*args)))
    except Exception as exc:  # the type and message are the contract
        return ("error", type(exc).__name__, str(exc))


def both(value: str, insecure: bool) -> tuple[Outcome, Outcome]:
    return (
        outcome(lambda: oracle.normalize_dns(value, insecure=insecure)),
        outcome(_core.normalize_dns, value, insecure),
    )


HOSTS = [
    "customer-acme.quilt.example",
    "nightly.quilttest.com",
    "NIGHTLY.QuiltTest.COM",
    "  nightly.quilttest.com  ",
    "\tnightly.quilttest.com\n",
    "a",
    "a.b",
    "xn--bcher-kva.example",
    "under_score.example",
    "trailing.dot.example.",
    "host/with/path",
    "host//double",
    "host/",
    "host?query=1",
    "host#frag",
    "user@host.example",
    "host:",
    "localhost",
    "LOCALHOST",
    " localhost ",
    "10.0.0",
    "1.2.3.4.5",
    "1234.1.1.1",
    "10.0.0.5",
    "999.999.999.999",
    "1.2.3.4",
    "::1",
    "[::1]",
    "[",
    "",
    " ",
    "\u00a0",
    "\u3000x.example\u2028",
    "\u001cx.example\u0085",
    "\u200bzero.width",
    "ÀÉ.EXAMPLE",
    "İ.example",
    "ΣΑΣ.example",
    "host:8443",
    "host:0",
    "host:65536",
    "host:00443",
    "host:abc",
    "host:1_0",
    "host:+1",
    "host:-1",
    "host: 1",
    "host:1 ",
    "host: ",
    "host:1:2",
    "a:b:c",
    ":443",
    "::",
    ":",
]

SCHEMES = [
    "https://",
    "HTTPS://",
    "Https://",
    "http://",
    "HTTP://",
    "ftp://",
    "://",
    "ht tp://",
    "x+y-z.1://",
    "1http://",
]
URL_TAILS = [
    "x.example",
    "X.Example/",
    "x.example/a/b?c=d#e",
    "x.example?q",
    "x.example#f",
    "user@x.example",
    "user:pw@x.example",
    "user:pw@x.example:8443",
    "x.example:",
    "x.example:443",
    "x.example:0",
    "x.example:65535",
    "x.example:65536",
    "x.example:000065535",
    "x.example:99999999999999999999",
    "x.example:abc",
    "x.example:1a",
    "x.example:\u0663",
    "x.example\t",
    "x.\texample",
    "x.example\n",
    "10.0.0.5",
    "10.0.0.5:443",
    "[::1]",
    "[::1]:443",
    "[::1]/path",
    "[FE80::1%25eth0]",
    "[FE80::1%eth0]",
    "[v1.fe80::a+en1]",
    "[v1]",
    "[vx.y]",
    "[1.2.3.4]",
    "[2001:db8::1]:abc",
    "[::1",
    "::1]",
    "]x[",
    "",
    "/path",
    "@",
    "@x.example",
    "x.example@",
    "localhost",
    "LocalHost:80",
    "localhost.example",
    "ex ample.com",
    "%41.example",
    "x.example%zone",
    "é.example",
    "İ.example",
]

# Python 3.12 changed how a port is read (``isdigit() and isascii()`` rather than
# ``int()``), 3.11.4 started validating the text inside ``[...]``, and 3.11 stopped
# taking ``1http`` for a scheme. Rust follows the new behaviour, so on the older
# interpreters these inputs are not compared.
OLD_PORT = sys.version_info < (3, 12)
OLD_BRACKET = sys.version_info < (3, 11, 4)
OLD_SCHEME = sys.version_info < (
    3,
    11,
)  # a scheme could start with a digit, "+", "-" or "."


def version_sensitive(value: str) -> bool:
    tail = value.split("://", 1)[-1] if "://" in value else ""
    if OLD_PORT and "://" in value:
        port = tail.rsplit("@", 1)[-1].partition("]")[2] if "[" in tail else tail
        port = port.partition(":")[2]
        for end in "/?#":
            port = port.partition(end)[0]
        if port and not port.isascii() or any(c in port for c in "+-_ \t\n\r\x0b\x0c"):
            return True
    if OLD_BRACKET and "[" in value and "]" in value:
        return True
    if OLD_SCHEME:
        cleaned = re.sub(r"[\t\r\n]", "", value.strip()).lstrip(
            "".join(map(chr, range(33)))
        )
        if re.match(r"[0-9+.-][A-Za-z0-9+.-]*:", cleaned):
            return True
    return False


@pytest.mark.parametrize("insecure", [False, True])
@pytest.mark.parametrize("value", HOSTS)
def test_hosts_table(value: str, insecure: bool) -> None:
    old, new = both(value, insecure)
    assert new == old


@pytest.mark.parametrize("insecure", [False, True])
@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("tail", URL_TAILS)
def test_urls_table(scheme: str, tail: str, insecure: bool) -> None:
    value = scheme + tail
    if version_sensitive(value):
        pytest.skip("Python's own answer differs on this version")
    old, new = both(value, insecure)
    assert new == old


TOKENS = [
    "https://", "http://", "HTTPS://", "ftp://", "://", "",
    "a", "B", "x.example", "localhost", "LocalHost", "10.0.0.5", "1", "0", "443",
    "99999", "-", ".", "_", ":", "@", "/", "?", "#", "%", "[", "]", "::1", " ", "\t",
    "~", "\u00e9", "\u0130",
]  # fmt: skip


# The same walk over awkward text: control characters, Unicode whitespace, decimal
# digits from other scripts, compatibility characters (U+2100 normalizes to "a/c"),
# case-folding oddities and an astral character.
WIDE_TOKENS = [
    "https://", "http://", "x.example", "a", ":", "/", "@", "[", "]", "%", "1", "443",
    "::1", "10.0.0.5", "\x00", "\x1f", "\x7f", "\u0663", "\uff11", "\u2100", "\u00df",
    "\u212a", "\u00a0", "\u2028", "\u0130", "\u03a3", "\U0001f600",
]  # fmt: skip


def random_inputs(count: int, seed: int, tokens: list[str] = TOKENS) -> list[str]:
    rng = random.Random(seed)
    return [
        "".join(rng.choice(tokens) for _ in range(rng.randint(0, 9)))
        for _ in range(count)
    ]


def test_random_walk_agrees_with_the_oracle() -> None:
    compared = 0
    for value in random_inputs(30_000, seed=20261113):
        if version_sensitive(value):
            continue
        for insecure in (False, True):
            old, new = both(value, insecure)
            assert new == old, f"{value!r} insecure={insecure}"
            compared += 1
    assert compared > 40_000


def test_undecodable_text_is_a_value_error_not_a_crash() -> None:
    # Python used to carry a lone surrogate (from an undecodable argv byte) through;
    # Rust cannot receive one, so the wrapper reports it as a ValueError.
    with pytest.raises(ValueError, match="not valid text"):
        _native.normalize_dns("bad\udcffhost.example")


def test_random_walk_over_awkward_text_agrees_with_the_oracle() -> None:
    compared = 0
    for value in random_inputs(20_000, seed=7, tokens=WIDE_TOKENS):
        if version_sensitive(value):
            continue
        for insecure in (False, True):
            old, new = both(value, insecure)
            assert new == old, f"{value!r} insecure={insecure}"
            compared += 1
    assert compared > 10_000


def test_identity_module_uses_the_core() -> None:
    from quiltx import identity

    for value in ("HTTPS://Nightly.QuiltTest.com/", "host:8443", "http://x"):
        assert outcome(identity.normalize_dns, value) == outcome(
            _core.normalize_dns, value, False
        )
    # A truthy non-bool still means "insecure", as it did in Python.
    assert identity.normalize_dns("localhost", insecure=1) == "localhost"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Credential paths
# ---------------------------------------------------------------------------

POSIX = sys.platform != "win32"


def path_pair() -> tuple[Outcome, Outcome, Outcome, Outcome]:
    return (
        outcome(oracle.fallback_path),
        outcome(_native.credentials_file),
        outcome(oracle.index_path),
        outcome(_native.credentials_index_file),
    )


def test_paths_on_this_machine_as_it_is() -> None:
    old_file, new_file, old_index, new_index = path_pair()
    assert new_file == old_file
    assert new_index == old_index
    assert Path(new_file[1]).name == "credentials.json"
    assert Path(new_index[1]).name == "credentials_index.json"


XDG = [
    None,
    "",
    "   ",
    "\t",
    "/data",
    "/data/",
    "/a//b/./c/",
    "rel",
    ".",
    "//two",
    "///three",
    "/a/../b",
    "/sp ace",
    "/ünï",
]
HOMES = [None, "", "/", "/home/u", "/home/u/", "/home/u///", "rel", "/Users/u"]


def platformdirs_version() -> tuple[int, ...]:
    return tuple(int(part) for part in platformdirs.__version__.split(".")[:3])


def platformdirs_differs(xdg: str | None, home: str | None) -> str | None:
    """Why an older platformdirs would answer differently from Rust, if it would.

    Rust follows platformdirs 4.14. Older releases treated these inputs
    differently (see rust/src/paths.rs), and quiltx does not pin the version.
    """
    version = platformdirs_version()
    xdg_used = xdg is not None and xdg.startswith("/")
    if xdg_used and sys.platform == "darwin" and version < (4, 6):
        return "macOS ignored XDG_DATA_HOME before platformdirs 4.6"
    if xdg in ("rel", ".") and version < (4, 12):
        return "a relative XDG_DATA_HOME was used as is before platformdirs 4.12"
    if not xdg_used and home == "" and version < (4, 12):
        return "an empty HOME was used verbatim before platformdirs 4.12"
    if not xdg_used and home == "rel" and version < (4, 14):
        return "a relative HOME was used as is before platformdirs 4.14"
    return None


@pytest.mark.skipif(
    not POSIX, reason="XDG_DATA_HOME and HOME do not move the Windows path"
)
@pytest.mark.parametrize("home", HOMES)
@pytest.mark.parametrize("xdg", XDG)
def test_paths_follow_xdg_and_home(monkeypatch: pytest.MonkeyPatch, xdg, home) -> None:
    reason = platformdirs_differs(xdg, home)
    if reason:
        pytest.skip(reason)
    for name, value in (("XDG_DATA_HOME", xdg), ("HOME", home)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    old_file, new_file, old_index, new_index = path_pair()
    assert new_file == old_file
    assert new_index == old_index


@pytest.mark.skipif(not POSIX, reason="needs a POSIX environment")
def test_paths_without_a_home_use_the_passwd_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    old_file, new_file, _, _ = path_pair()
    assert new_file == old_file


@pytest.mark.parametrize(
    "dns", ["nightly.quilttest.com", "Mixed.Case.Example", "", "ünï.example", "a b"]
)
def test_keyring_entry_matches_the_old_call(dns: str) -> None:
    assert _native.keyring_entry(dns) == oracle.keyring_entry(dns)


@pytest.mark.skipif(not POSIX, reason="XDG_DATA_HOME does not move the Windows path")
def test_store_writes_where_the_oracle_says(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(store, "_keyring_available", lambda: False)
    monkeypatch.setattr(store, "_FILE_FALLBACK_WARNED", True)
    store.store("nightly.quilttest.com", "qk_abc")
    written = oracle.fallback_path()
    assert written.is_file() and written == _native.credentials_file()
    assert store.get("nightly.quilttest.com") == {
        "api_key": "qk_abc",
        "name": None,
        "expires_at": None,
    }
    store.delete("nightly.quilttest.com")
    assert store.get("nightly.quilttest.com") is None


# ---------------------------------------------------------------------------
# File-backed store
# ---------------------------------------------------------------------------


def file_pair(tmp: Path, name: str) -> tuple[Path, Path]:
    old = tmp / "old" / name
    new = tmp / "new" / name
    return old, new


def test_fallback_bytes_and_modes_match_the_oracle(tmp_path: Path) -> None:
    old, new = file_pair(tmp_path, "credentials.json")
    entries = [
        ("nightly.quilttest.com", "qk_abc", None, None),
        ("a.example.com", "qk_a", "alice-key", 1_800_000_000),
        ("ünï.example", "qk_x", "naïve", None),
    ]
    for dns, key, name, expires in entries:
        oracle.store_fallback(old, dns, key, name, expires)
        _core.store_fallback(new, dns, key, name, expires)
    assert new.read_bytes() == old.read_bytes()
    if POSIX:
        assert oct(new.stat().st_mode)[-3:] == "600"
        assert oct(old.stat().st_mode)[-3:] == "600"
        assert oct(new.parent.stat().st_mode)[-3:] == "700"
        assert oct(old.parent.stat().st_mode)[-3:] == "700"
    assert _core.read_fallback(new) == oracle.read_fallback(old)
    assert _core.get_fallback(new, "a.example.com") == oracle.get_fallback(
        old, "a.example.com"
    )
    assert _core.list_fallback(new) == oracle.list_fallback(old)
    _core.delete_fallback(new, "a.example.com")
    oracle.delete_fallback(old, "a.example.com")
    assert new.read_bytes() == old.read_bytes()
    assert _core.get_fallback(new, "a.example.com") is None
    _core.delete_fallback(new, "a.example.com")
    oracle.delete_fallback(old, "a.example.com")
    assert new.read_bytes() == old.read_bytes()


def test_index_bytes_match_the_oracle(tmp_path: Path) -> None:
    old, new = file_pair(tmp_path, "credentials_index.json")
    for dns in ("a.example.com", "b.example.com", "a.example.com"):
        oracle.add_to_index(old, dns)
        _core.add_to_index(new, dns)
    assert new.read_bytes() == old.read_bytes()
    assert new.read_text(encoding="utf-8") == '["a.example.com", "b.example.com"]'
    assert _core.read_index(new) == oracle.read_index(old)
    _core.remove_from_index(new, "a.example.com")
    oracle.remove_from_index(old, "a.example.com")
    assert new.read_bytes() == old.read_bytes()
    _core.remove_from_index(new, "a.example.com")
    oracle.remove_from_index(old, "a.example.com")
    assert new.read_bytes() == old.read_bytes()


def test_store_validation_matches_the_oracle(tmp_path: Path) -> None:
    old, new = file_pair(tmp_path, "credentials.json")
    for key in ("", "   ", "not-a-key"):
        assert outcome(oracle.store_fallback, old, "x.example.com", key) == outcome(
            _core.store_fallback, new, "x.example.com", key
        )
        assert not old.exists() and not new.exists()
    oracle.store_fallback(old, "x.example.com", "  qk_ok  ")
    _core.store_fallback(new, "x.example.com", "  qk_ok  ")
    assert new.read_bytes() == old.read_bytes()
    got = _core.get_fallback(new, "x.example.com")
    assert got is not None and got["api_key"] == "qk_ok"


def test_malformed_and_legacy_files_match_the_oracle(tmp_path: Path) -> None:
    for name, body in (
        ("missing", None),
        ("bad.json", "not-json"),
        ("list.json", "[]"),
        (
            "legacy.json",
            '{"old.example.com": {"username": "u", "secret": "s"}}',
        ),
    ):
        old, new = file_pair(tmp_path, name)
        if body is not None:
            old.parent.mkdir(parents=True, exist_ok=True)
            new.parent.mkdir(parents=True, exist_ok=True)
            old.write_text(body)
            new.write_text(body)
        assert _core.read_fallback(new) == oracle.read_fallback(old)
        assert outcome(_core.get_fallback, new, "old.example.com") == outcome(
            oracle.get_fallback, old, "old.example.com"
        )
        assert outcome(_core.list_fallback, new) == outcome(oracle.list_fallback, old)
        assert _core.read_index(new) == oracle.read_index(old)


def test_write_fallback_over_a_looser_file_tightens_the_mode(
    tmp_path: Path,
) -> None:
    if not POSIX:
        pytest.skip("POSIX permission bits do not exist on Windows")
    old, new = file_pair(tmp_path, "credentials.json")
    for path in (old, new):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
        path.chmod(0o644)
    oracle.store_fallback(old, "x.example.com", "qk_x")
    _core.store_fallback(new, "x.example.com", "qk_x")
    assert new.read_bytes() == old.read_bytes()
    assert oct(new.stat().st_mode)[-3:] == "600"
    assert oct(old.stat().st_mode)[-3:] == "600"


# ---------------------------------------------------------------------------
# The core is required
# ---------------------------------------------------------------------------


def run_python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )


@pytest.mark.parametrize(
    "module", ["quiltx.cli", "quiltx.identity", "quiltx.stack", "quiltx.auth.store"]
)
def test_the_cli_path_needs_the_core(module: str) -> None:
    # `sys.modules[name] = None` makes `import name` raise ImportError.
    blocked = run_python(
        f"import sys; sys.modules['quiltx._core'] = None; import {module}"
    )
    assert blocked.returncode != 0
    assert "quiltx's compiled core (quiltx._core) is missing" in blocked.stderr
    assert run_python(f"import {module}").returncode == 0
