"""The only importer of the compiled ``quiltx._core`` extension.

Everything Rust-backed that auth needs goes through this module, so the
boundary between the Python auth code and the Rust core is one file. Today the
core exposes two functions that prove the boundary works; no auth behaviour
depends on them yet. Nothing imports this module on the normal CLI path, so a
checkout without the compiled extension still runs.
"""

from __future__ import annotations

from quiltx import _core


def core_version() -> str:
    """Version of the Rust crate behind ``quiltx._core``."""
    return _core.core_version()


def ping(message: str) -> str:
    """Round-trip *message* through Rust; returns ``pong:<message>``."""
    return _core.ping(message)
