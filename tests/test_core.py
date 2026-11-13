"""The compiled Rust extension, directly and through quiltx.auth._native.

These run against whatever quiltx is installed in the environment: in CI that
is the built wheel, so a broken or missing extension fails here.
"""

from __future__ import annotations

from quiltx import _core
from quiltx.auth import _native


def test_ping_round_trips_a_string() -> None:
    assert _core.ping("x") == "pong:x"
    assert _core.ping("") == "pong:"
    assert _core.ping("héllo ✓") == "pong:héllo ✓"


def test_core_version_is_semver_shaped() -> None:
    parts = _core.core_version().split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_native_wrapper_delegates_to_the_extension() -> None:
    assert _native.ping("hi") == "pong:hi"
    assert _native.core_version() == _core.core_version()


def test_extension_is_the_compiled_module() -> None:
    # A Python file named _core.py would shadow the extension; require a
    # compiled module (an extension, not source).
    assert not (getattr(_core, "__file__", "") or "").endswith(".py")
