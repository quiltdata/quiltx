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


def test_invalid_utf8_raises_and_does_not_overwrite(tmp_path: Path) -> None:
    body = b'{"keep": {"api_key": "qk_keep", "name": null, "expires_at": null}, "x": "\xff"}'
    old, new = file_pair(tmp_path, "credentials.json")
    for path in (old, new):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    for fn, path, args in (
        (oracle.read_fallback, old, ()),
        (_core.read_fallback, new, ()),
        (oracle.store_fallback, old, ("x.example.com", "qk_x")),
        (_core.store_fallback, new, ("x.example.com", "qk_x")),
        (oracle.delete_fallback, old, ("keep",)),
        (_core.delete_fallback, new, ("keep",)),
    ):
        with pytest.raises(UnicodeDecodeError):
            fn(path, *args)
    assert new.read_bytes() == body
    assert old.read_bytes() == body


def test_nan_does_not_reset_the_file(tmp_path: Path) -> None:
    body = b'{"keep": {"api_key": "qk_keep", "name": null, "expires_at": NaN}}'
    old, new = file_pair(tmp_path, "credentials.json")
    for path in (old, new):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    got = oracle.read_fallback(old)
    expires = got["keep"]["expires_at"]
    assert expires != expires  # NaN
    with pytest.raises(ValueError):
        _core.read_fallback(new)
    with pytest.raises(ValueError):
        _core.store_fallback(new, "x.example.com", "qk_x")
    with pytest.raises(ValueError):
        _core.delete_fallback(new, "keep")
    assert new.read_bytes() == body
    assert old.read_bytes() == body


def test_lone_surrogates_do_not_reset_the_file(tmp_path: Path) -> None:
    bodies = (
        b'{"a":"\\ud800"}',
        b'{"a":"\\ud800abc"}',
        b'{"\\ud800":1}',
    )
    for i, body in enumerate(bodies):
        old, new = file_pair(tmp_path, f"surrogate-{i}.json")
        for path in (old, new):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        got = oracle.read_fallback(old)
        assert got, body
        with pytest.raises(ValueError):
            _core.read_fallback(new)
        with pytest.raises(ValueError):
            _core.store_fallback(new, "x.example.com", "qk_x")
        with pytest.raises(ValueError):
            _core.delete_fallback(new, "a")
        assert new.read_bytes() == body
        assert old.read_bytes() == body


def test_out_of_range_numbers_match_the_oracle(tmp_path: Path) -> None:
    bodies = (
        b'{"n": 1e400}',
        b'{"n": -1e400}',
        b'{"n": ' + b"1" * 400 + b"}",
    )
    for i, body in enumerate(bodies):
        old, new = file_pair(tmp_path, f"num-{i}.json")
        for path in (old, new):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        assert _core.read_fallback(new) == oracle.read_fallback(old)
        _core.store_fallback(new, "x.example.com", "qk_x")
        oracle.store_fallback(old, "x.example.com", "qk_x")
        rust = _core.read_fallback(new)
        py = oracle.read_fallback(old)
        assert rust == py
        assert "n" in rust
        assert rust["x.example.com"]["api_key"] == "qk_x"


class MemoryKeyring:
    """A dict-backed stand-in for the ``keyring`` module."""

    def __init__(self) -> None:
        self.stored: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.stored.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.stored[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.stored.pop((service, username), None)


def test_keyring_store_bytes_and_list_match_the_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_kr, new_kr = MemoryKeyring(), MemoryKeyring()
    old_index, new_index = file_pair(tmp_path, "credentials_index.json")
    old_fb, new_fb = file_pair(tmp_path, "credentials.json")
    monkeypatch.setattr("keyring.get_password", new_kr.get_password)
    monkeypatch.setattr("keyring.set_password", new_kr.set_password)
    monkeypatch.setattr("keyring.delete_password", new_kr.delete_password)
    entries = [
        ("nightly.quilttest.com", "qk_abc", None, None),
        ("a.example.com", "qk_a", "alice-key", 1_800_000_000),
    ]
    for dns, key, name, expires in entries:
        oracle.store(
            dns,
            key,
            name=name,
            expires_at=expires,
            use_keyring=True,
            fallback_path=old_fb,
            index_path=old_index,
            backend=old_kr,
        )
        _core.store_credential(dns, key, name, expires, True, new_fb, new_index)
    assert not old_fb.exists() and not new_fb.exists()
    assert new_index.read_bytes() == old_index.read_bytes()
    service = "quiltx"
    for dns, _, _, _ in entries:
        assert new_kr.get_password(service, dns) == old_kr.get_password(service, dns)
    assert _core.list_credentials(True, new_fb, new_index) == oracle.catalog_list(
        use_keyring=True,
        fallback_path=old_fb,
        index_path=old_index,
        backend=old_kr,
    )
    assert _core.get_credential("a.example.com", True, new_fb) == oracle.get(
        "a.example.com",
        use_keyring=True,
        fallback_path=old_fb,
        backend=old_kr,
    )
    _core.delete_credential("a.example.com", True, new_fb, new_index)
    oracle.delete(
        "a.example.com",
        use_keyring=True,
        fallback_path=old_fb,
        index_path=old_index,
        backend=old_kr,
    )
    assert new_index.read_bytes() == old_index.read_bytes()
    assert new_kr.get_password(service, "a.example.com") is None
    assert old_kr.get_password(service, "a.example.com") is None
    _core.delete_credential("a.example.com", True, new_fb, new_index)
    oracle.delete(
        "a.example.com",
        use_keyring=True,
        fallback_path=old_fb,
        index_path=old_index,
        backend=old_kr,
    )


def test_corrupt_keyring_entry_raises_instead_of_looking_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_kr, new_kr = MemoryKeyring(), MemoryKeyring()
    old_kr.set_password("quiltx", "x.example.com", "not-json")
    new_kr.set_password("quiltx", "x.example.com", "not-json")
    fallback = tmp_path / "fb.json"
    monkeypatch.setattr("keyring.get_password", new_kr.get_password)
    monkeypatch.setattr("keyring.set_password", new_kr.set_password)
    # Old Python treated corrupt JSON as missing.
    assert (
        oracle.get(
            "x.example.com",
            use_keyring=True,
            fallback_path=fallback,
            backend=old_kr,
        )
        is None
    )
    with pytest.raises(ValueError, match="x.example.com") as raised:
        _core.get_credential("x.example.com", True, fallback)
    msg = str(raised.value)
    assert "not valid JSON" in msg
    assert "quiltx catalog login --catalog x.example.com" in msg
    assert "quiltx catalog forget x.example.com" in msg
    # A later store must not have already replaced the payload (get does not write).
    assert new_kr.get_password("quiltx", "x.example.com") == "not-json"


def test_keyring_validation_matches_the_oracle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_kr, new_kr = MemoryKeyring(), MemoryKeyring()
    old_fb, new_fb = file_pair(tmp_path, "credentials.json")
    old_index, new_index = file_pair(tmp_path, "credentials_index.json")
    monkeypatch.setattr("keyring.set_password", new_kr.set_password)
    for key in ("", "   ", "not-a-key"):
        assert outcome(
            lambda k=key: oracle.store(
                "x.example.com",
                k,
                use_keyring=True,
                fallback_path=old_fb,
                index_path=old_index,
                backend=old_kr,
            )
        ) == outcome(
            _core.store_credential,
            "x.example.com",
            key,
            None,
            None,
            True,
            new_fb,
            new_index,
        )
        assert not old_kr.stored and not new_kr.stored


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


def test_get_password_bytes_are_decoded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kr = MemoryKeyring()
    payload = '{"api_key": "qk_bytes", "name": null, "expires_at": null}'
    kr.stored[("quiltx", "x.example.com")] = payload

    def get_bytes(service: str, username: str):
        value = kr.get_password(service, username)
        return None if value is None else value.encode()

    monkeypatch.setattr("keyring.get_password", get_bytes)
    entry = _core.get_credential("x.example.com", True, tmp_path / "fb.json")
    assert entry is not None
    assert entry["api_key"] == "qk_bytes"


def test_keyring_exceptions_pass_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("keyring is on fire")

    monkeypatch.setattr("keyring.get_password", boom)
    monkeypatch.setattr("keyring.set_password", boom)
    monkeypatch.setattr("keyring.delete_password", boom)
    fallback, index = tmp_path / "fb.json", tmp_path / "idx.json"
    with pytest.raises(RuntimeError, match="keyring is on fire"):
        _core.get_credential("x.example.com", True, fallback)
    with pytest.raises(RuntimeError, match="keyring is on fire"):
        _core.store_credential(
            "x.example.com", "qk_x", None, None, True, fallback, index
        )
    with pytest.raises(RuntimeError, match="keyring is on fire"):
        _core.delete_credential("x.example.com", True, fallback, index)
    with pytest.raises(RuntimeError, match="keyring is on fire"):
        # Index must exist so list reaches the keyring, not just an empty file.
        _core.write_index(index, ["x.example.com"])
        _core.list_credentials(True, fallback, index)


def test_list_skips_a_corrupt_keyring_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    kr = MemoryKeyring()
    fallback, index = tmp_path / "fb.json", tmp_path / "idx.json"
    monkeypatch.setattr("keyring.get_password", kr.get_password)
    monkeypatch.setattr("keyring.set_password", kr.set_password)
    _core.store_credential(
        "good.example.com", "qk_good", None, None, True, fallback, index
    )
    _core.add_to_index(index, "bad.example.com")
    kr.set_password("quiltx", "bad.example.com", "not-json")
    listed = _core.list_credentials(True, fallback, index)
    assert [dns for dns, _ in listed] == ["good.example.com"]
    err = capfd.readouterr().err
    assert "bad.example.com" in err
    assert "skipping corrupt keyring entry" in err
    assert kr.get_password("quiltx", "bad.example.com") == "not-json"


def test_store_and_delete_over_a_corrupt_keyring_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kr = MemoryKeyring()
    fallback, index = tmp_path / "fb.json", tmp_path / "idx.json"
    monkeypatch.setattr("keyring.get_password", kr.get_password)
    monkeypatch.setattr("keyring.set_password", kr.set_password)
    monkeypatch.setattr("keyring.delete_password", kr.delete_password)
    kr.set_password("quiltx", "x.example.com", "not-json")
    _core.write_index(index, ["x.example.com"])
    _core.store_credential("x.example.com", "qk_new", None, None, True, fallback, index)
    entry = _core.get_credential("x.example.com", True, fallback)
    assert entry is not None
    assert entry["api_key"] == "qk_new"
    kr.set_password("quiltx", "x.example.com", "not-json")
    _core.delete_credential("x.example.com", True, fallback, index)
    assert _core.get_credential("x.example.com", True, fallback) is None
    assert kr.get_password("quiltx", "x.example.com") is None


# ---------------------------------------------------------------------------
# Registry HTTP
# ---------------------------------------------------------------------------


CREATED = {
    "data": {
        "apiKeyCreate": {
            "__typename": "APIKeyCreated",
            "apiKey": {
                "id": "ak-1",
                "name": "quiltx-host",
                "expiresAt": "2027-05-04T00:00:00Z",
            },
            "secret": "qk_thesecret",
        }
    }
}


def _patch_http(
    monkeypatch: pytest.MonkeyPatch, *, get=None, post_json=None, post_form=None
):
    if get is not None:
        monkeypatch.setattr(oracle, "_get_json", get)
        monkeypatch.setattr("quiltx.auth.registry._get_json", get)
    if post_json is not None:
        monkeypatch.setattr(oracle, "_post_json", post_json)
        monkeypatch.setattr("quiltx.auth.registry._post_json", post_json)
    if post_form is not None:
        monkeypatch.setattr(oracle, "_post_form", post_form)
        monkeypatch.setattr("quiltx.auth.registry._post_form", post_form)


def test_resolve_registry_url_matches_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def get_json(url: str):
        assert url == "https://catalog.example.com/config.json"
        return {"registryUrl": "https://reg.example.com/"}

    _patch_http(monkeypatch, get=get_json)
    assert outcome(
        _core.resolve_registry_url, "https://catalog.example.com/"
    ) == outcome(oracle.resolve_registry_url, "https://catalog.example.com/")
    assert (
        _core.resolve_registry_url("https://catalog.example.com/")
        == "https://reg.example.com"
    )


def test_resolve_registry_url_fallback_matches_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_http(monkeypatch, get=lambda url: {"foo": 1})
    assert outcome(_core.resolve_registry_url, "http://localhost/") == outcome(
        oracle.resolve_registry_url, "http://localhost/"
    )


def test_resolve_does_not_fall_back_when_config_fetch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.registry import CatalogAuthError

    def get_json(url: str):
        raise CatalogAuthError(f"Request to {url} failed (404): missing")

    _patch_http(monkeypatch, get=get_json)
    assert outcome(
        _core.resolve_registry_url, "https://catalog.example.com"
    ) == outcome(oracle.resolve_registry_url, "https://catalog.example.com")
    with pytest.raises(CatalogAuthError, match="404"):
        _core.resolve_registry_url("https://catalog.example.com")


def test_non_object_config_raises_instead_of_looking_like_a_missing_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.registry import CatalogAuthError

    _patch_http(monkeypatch, get=lambda url: ["not", "a", "map"])
    with pytest.raises(CatalogAuthError, match="not a JSON object"):
        _core.resolve_registry_url("https://catalog.example.com")
    # The old Python called .get on a list and raised AttributeError, which a
    # caller could mistake for an unexpected bug and retry against the catalog.
    with pytest.raises(AttributeError):
        oracle.resolve_registry_url("https://catalog.example.com")


def test_login_token_and_create_match_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        if url.endswith("/api/login"):
            assert payload == {"username": "admin", "password": "hunter2"}
            return {"refresh_token": "rt-abc"}
        if url.endswith("/graphql"):
            assert bearer == "at-xyz"
            return CREATED
        raise AssertionError(url)

    def post_form(url: str, payload: dict):
        assert url.endswith("/api/token")
        assert payload == {"refresh_token": "rt-abc"}
        return {"access_token": "at-xyz"}

    _patch_http(monkeypatch, post_json=post_json, post_form=post_form)
    assert outcome(
        _core.acquire_refresh_token, "https://catalog.example.com", "admin", "hunter2"
    ) == outcome(
        oracle.acquire_refresh_token, "https://catalog.example.com", "admin", "hunter2"
    )
    assert outcome(
        _core.exchange_refresh_token_for_access_token,
        "https://catalog.example.com",
        "rt-abc",
    ) == outcome(
        oracle.exchange_refresh_token_for_access_token,
        "https://catalog.example.com",
        "rt-abc",
    )
    assert outcome(
        _core.create_api_key,
        "https://catalog.example.com",
        "at-xyz",
        "quiltx-host",
        365,
    ) == outcome(
        lambda: oracle.create_api_key(
            "https://catalog.example.com",
            "at-xyz",
            name="quiltx-host",
            expires_in_days=365,
        )
    )


def test_missing_tokens_and_graphql_errors_match_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        if url.endswith("/api/login"):
            return {"foo": "bar"}
        if "InvalidInput" in str(payload):
            return payload
        return {"errors": [{"message": "Unauthorized"}]}

    def post_json_invalid(url: str, payload: dict, *, bearer: str | None = None):
        return {
            "data": {
                "apiKeyCreate": {
                    "__typename": "InvalidInput",
                    "errors": [{"path": "name", "message": "name in use"}],
                }
            }
        }

    def post_form(url: str, payload: dict):
        return {"foo": "bar"}

    _patch_http(monkeypatch, post_json=post_json, post_form=post_form)
    assert outcome(
        _core.acquire_refresh_token, "https://catalog.example.com", "a", "b"
    ) == outcome(oracle.acquire_refresh_token, "https://catalog.example.com", "a", "b")
    assert outcome(
        _core.exchange_refresh_token_for_access_token,
        "https://catalog.example.com",
        "rt",
    ) == outcome(
        oracle.exchange_refresh_token_for_access_token,
        "https://catalog.example.com",
        "rt",
    )
    _patch_http(monkeypatch, post_json=post_json_invalid)
    assert outcome(
        _core.create_api_key, "https://catalog.example.com", "at", "dup", 90
    ) == outcome(
        lambda: oracle.create_api_key(
            "https://catalog.example.com", "at", name="dup", expires_in_days=90
        )
    )


def test_validate_and_bootstrap_match_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def get_json(url: str):
        return {"registryUrl": "https://reg.example.com"}

    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        if url.endswith("/api/login"):
            return {"refresh_token": "rt"}
        if url.endswith("/graphql") and payload.get("operationName") == "apiKeysList":
            if bearer == "qk_bad":
                return {"errors": [{"message": "Unauthorized"}]}
            return {"data": {"apiKeysList": {"apiKeys": []}}}
        return CREATED

    def post_form(url: str, payload: dict):
        return {"access_token": "at"}

    _patch_http(monkeypatch, get=get_json, post_json=post_json, post_form=post_form)
    assert outcome(
        _core.validate_api_key, "https://reg.example.com", "qk_test"
    ) == outcome(
        lambda: oracle.validate_api_key("https://catalog.example.com", "qk_test")
    )
    assert outcome(
        _core.validate_api_key, "https://reg.example.com", "qk_bad"
    ) == outcome(
        lambda: oracle.validate_api_key("https://catalog.example.com", "qk_bad")
    )
    from quiltx.auth import registry as quilt_auth

    assert outcome(
        lambda: quilt_auth.bootstrap_api_key(
            "https://catalog.example.com",
            username="admin",
            password="hunter2",
            name="quiltx-host",
            expires_in_days=365,
        )
    ) == outcome(
        lambda: oracle.bootstrap_api_key(
            "https://catalog.example.com",
            username="admin",
            password="hunter2",
            name="quiltx-host",
            expires_in_days=365,
        )
    )


def test_validate_rejects_a_non_object_body(monkeypatch: pytest.MonkeyPatch) -> None:
    from quiltx.auth.registry import CatalogAuthError

    bodies: list[object] = [[], None, "ok", 1, True, ""]
    for body in bodies:
        _patch_http(
            monkeypatch, post_json=lambda url, payload, *, bearer=None, b=body: b
        )
        with pytest.raises(
            CatalogAuthError, match="Unexpected response from"
        ) as raised:
            _core.validate_api_key("https://reg.example.com", "qk_test")
        # The old Python treated a non-object 200 as success (no .get("errors")).
        # Do not compare with the oracle on this path.
        assert "https://reg.example.com/graphql" in str(raised.value)


def test_error_text_escapes_like_the_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        return {"errors": [{"message": 'no\nkey and it\'s "quoted"'}]}

    _patch_http(monkeypatch, post_json=post_json)
    assert outcome(
        _core.create_api_key, "https://catalog.example.com", "at", "x", 90
    ) == outcome(
        lambda: oracle.create_api_key(
            "https://catalog.example.com", "at", name="x", expires_in_days=90
        )
    )


def test_create_api_key_coerces_name_and_expires_in_days(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth import registry as quilt_auth

    calls: list[dict] = []

    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        calls.append(payload)
        return CREATED

    monkeypatch.setattr(quilt_auth, "_post_json", post_json)
    out = quilt_auth.create_api_key(
        "https://catalog.example.com",
        "at-xyz",
        name=123,  # type: ignore[arg-type]
        expires_in_days="365",  # type: ignore[arg-type]
    )
    assert out["secret"] == "qk_thesecret"
    assert calls[0]["variables"] == {"input": {"name": "123", "expiresInDays": 365}}


def test_non_string_registry_url_matches_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_http(monkeypatch, get=lambda url: {"registryUrl": 123})
    assert outcome(
        _core.resolve_registry_url, "https://catalog.example.com"
    ) == outcome(oracle.resolve_registry_url, "https://catalog.example.com")
    assert _core.resolve_registry_url("https://catalog.example.com") == "123"
    _patch_http(monkeypatch, get=lambda url: {"registryUrl": True})
    assert _core.resolve_registry_url("https://catalog.example.com") == "True"
    assert oracle.resolve_registry_url("https://catalog.example.com") == "True"


def test_error_text_uses_python_repr_for_c1_bidi_and_line_separators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.registry import CatalogAuthError

    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        return {"errors": [{"message": "bad\u2028key\x80end"}]}

    _patch_http(monkeypatch, post_json=post_json)
    with pytest.raises(CatalogAuthError) as raised:
        _core.create_api_key("https://catalog.example.com", "at", "x", 90)
    text = str(raised.value)
    assert "\\u2028" in text
    assert "\\x80" in text


def test_error_text_redacts_qk_values_and_sensitive_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.registry import CatalogAuthError

    def post_json(url: str, payload: dict, *, bearer: str | None = None):
        return {
            "errors": [
                {
                    "message": "qk_should_not_leak",
                    "access_token": "refresh_abc",
                    "PASSWORD": "hunter2",
                    "apiKey": "qk_also_hidden",
                    "hint": "not a secret",
                }
            ]
        }

    _patch_http(monkeypatch, post_json=post_json)
    with pytest.raises(CatalogAuthError) as raised:
        _core.create_api_key("https://catalog.example.com", "at", "x", 90)
    text = str(raised.value)
    assert "qk_should_not_leak" not in text
    assert "qk_also_hidden" not in text
    assert "refresh_abc" not in text
    assert "hunter2" not in text
    assert "<redacted>" in text
    assert "not a secret" in text


def test_lone_surrogate_in_response_is_catalog_auth_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth import registry as quilt_auth
    from quiltx.auth.registry import CatalogAuthError

    def get_json(url: str):
        return {"registryUrl": "https://reg.example.com/\ud800"}

    monkeypatch.setattr(quilt_auth, "_get_json", get_json)
    with pytest.raises(CatalogAuthError, match="Unexpected response from") as raised:
        quilt_auth.resolve_registry_url("https://catalog.example.com")
    assert "https://catalog.example.com/config.json" in str(raised.value)


def _patch_sts(monkeypatch: pytest.MonkeyPatch, get):
    monkeypatch.setattr(oracle, "_sts_get_json", get)
    monkeypatch.setattr("quiltx.auth.session._get_json", get)


def test_mint_registry_credentials_matches_the_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {
        "AccessKeyId": "ASIA",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2030-01-01T00:00:00Z",
    }

    def get_json(url: str):
        assert url == "https://registry.example.com/api/auth/get_credentials"
        return body

    _patch_sts(monkeypatch, get_json)
    assert outcome(
        _core.mint_registry_credentials, "https://registry.example.com/"
    ) == outcome(oracle.mint_registry_credentials, "https://registry.example.com/")
    assert _core.mint_registry_credentials("https://registry.example.com/") == {
        "access_key": "ASIA",
        "secret_key": "secret",
        "token": "token",
        "expiry_time": "2030-01-01T00:00:00Z",
    }


def test_mint_registry_credentials_incomplete_is_unusable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.session import CatalogCredentialsError

    _patch_sts(monkeypatch, lambda url: {"AccessKeyId": "ASIA"})
    with pytest.raises(
        CatalogCredentialsError, match="no usable credentials"
    ) as raised:
        _core.mint_registry_credentials("https://registry.example.com")
    assert "SecretAccessKey must be a non-empty string" in str(raised.value)
    # The old Python used a generic message for a missing key; do not
    # compare this path with the oracle.


def test_mint_rejects_null_empty_and_wrong_typed_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.session import CatalogCredentialsError

    happy = {
        "AccessKeyId": "ASIA",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2030-01-01T00:00:00Z",
    }
    cases: list[tuple[str, object, str]] = [
        ("AccessKeyId", None, "AccessKeyId"),
        ("AccessKeyId", "", "AccessKeyId"),
        ("AccessKeyId", 1, "AccessKeyId"),
        ("SecretAccessKey", None, "SecretAccessKey"),
        ("SecretAccessKey", "", "SecretAccessKey"),
        ("SessionToken", None, "SessionToken"),
        ("SessionToken", "", "SessionToken"),
    ]
    for field, bad, mention in cases:
        body = dict(happy)
        body[field] = bad  # type: ignore[assignment]
        _patch_sts(monkeypatch, lambda url, b=body: b)
        with pytest.raises(
            CatalogCredentialsError, match="no usable credentials"
        ) as raised:
            _core.mint_registry_credentials("https://registry.example.com")
        assert mention in str(raised.value)


def test_mint_rejects_a_naive_or_odd_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.session import CatalogCredentialsError

    happy = {
        "AccessKeyId": "ASIA",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
        "Expiration": "2030-01-01T00:00:00Z",
    }
    bads: list[object] = [
        None,
        "",
        1_730_000_000,
        "2030-01-01T00:00:00",
        "not-a-date",
        "NaN",
        float("nan"),
    ]
    for bad in bads:
        body = dict(happy)
        body["Expiration"] = bad  # type: ignore[assignment]
        _patch_sts(monkeypatch, lambda url, b=body: b)
        with pytest.raises(
            CatalogCredentialsError, match="no usable credentials"
        ) as raised:
            _core.mint_registry_credentials("https://registry.example.com")
        assert "Expiration must be a timezone-aware datetime string" in str(
            raised.value
        )


def test_mint_registry_credentials_rejects_a_non_object_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.session import CatalogCredentialsError

    cases: list[tuple[object, str]] = [
        ([], "list of length 0"),
        (None, "None"),
        ("ok", "str of length 2"),
        (1, "int"),
        (True, "bool"),
        ("", "str of length 0"),
        ("qk_should_not_leak", "str of length 18"),
    ]
    for body, typ in cases:
        _patch_sts(monkeypatch, lambda url, b=body: b)
        with pytest.raises(
            CatalogCredentialsError, match="no usable credentials"
        ) as raised:
            _core.mint_registry_credentials("https://registry.example.com")
        text = str(raised.value)
        assert (
            "unexpected response from https://registry.example.com/api/auth/get_credentials:"
            in text
        )
        assert typ in text
        assert "qk_should_not_leak" not in text
        # The old Python used the same generic message for a TypeError; do not
        # compare this path with the oracle.


def test_mint_non_object_error_does_not_echo_the_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.session import CatalogCredentialsError

    def get_json(url: str):
        return [
            {
                "SecretAccessKey": "leak_me",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "message": "bad\u2028key\x80end",
                "hint": "not a secret",
            }
        ]

    _patch_sts(monkeypatch, get_json)
    with pytest.raises(CatalogCredentialsError) as raised:
        _core.mint_registry_credentials("https://registry.example.com")
    text = str(raised.value)
    assert "list of length 1" in text
    assert "leak_me" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "not a secret" not in text
    assert "bad" not in text


def test_mint_lone_surrogate_in_response_is_catalog_credentials_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quiltx.auth.session import CatalogCredentialsError

    def get_json(url: str):
        return {
            "AccessKeyId": "ASIA\ud800",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": "2030-01-01T00:00:00Z",
        }

    _patch_sts(monkeypatch, get_json)
    with pytest.raises(
        CatalogCredentialsError, match="Unexpected response from"
    ) as raised:
        _core.mint_registry_credentials("https://registry.example.com")
    assert "https://registry.example.com/api/auth/get_credentials" in str(raised.value)


def test_resolve_credentials_matches_the_oracle() -> None:
    dns = "nightly.example"
    cases: list[tuple[object, ...]] = [
        ("qk_flag", "qk_env", "qk_stored", False, False, "cli"),
        ("", "qk_env", "qk_stored", False, False, "cli"),
        (None, "qk_env", "qk_stored", False, False, "cli"),
        (None, "", "qk_stored", False, False, "cli"),
        (None, None, "qk_stored", False, False, "cli"),
        (None, None, "", False, False, "api"),
        (None, None, "qk_stored", True, False, "api"),
        (None, None, "qk_stored", True, True, "cli"),
        (None, None, None, False, True, "cli"),
        (None, None, None, False, False, "cli"),
        (None, None, None, False, True, "api"),
        (None, None, None, False, False, "api"),
        ("qk_kw", None, None, True, False, "api"),
    ]
    for provided, env_key, stored_key, skip, allow, mode in cases:
        assert outcome(
            _core.resolve_credentials,
            dns,
            provided,
            env_key,
            stored_key,
            skip,
            allow,
            mode,
        ) == outcome(
            oracle.resolve_credentials,
            dns,
            provided,
            env_key,
            stored_key,
            skip,
            allow,
            mode,
        ), (
            provided,
            env_key,
            stored_key,
            skip,
            allow,
            mode,
        )


# ---------------------------------------------------------------------------
# The core is required
# ---------------------------------------------------------------------------


def run_python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )


@pytest.mark.parametrize(
    "module",
    [
        "quiltx.cli",
        "quiltx.identity",
        "quiltx.stack",
        "quiltx.auth.store",
        "quiltx.auth.registry",
    ],
)
def test_the_cli_path_needs_the_core(module: str) -> None:
    # `sys.modules[name] = None` makes `import name` raise ImportError.
    blocked = run_python(
        f"import sys; sys.modules['quiltx._core'] = None; import {module}"
    )
    assert blocked.returncode != 0
    assert "quiltx's compiled core (quiltx._core) is missing" in blocked.stderr
    assert run_python(f"import {module}").returncode == 0
