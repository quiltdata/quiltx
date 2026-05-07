"""Compatibility shim: expose the shared logs implementation.

Exports the public API from `quiltx.tools._logs_impl` so callers importing
`quiltx.tools.logs` keep working during the migration.
"""

from __future__ import annotations

from quiltx.tools import _logs_impl as _impl

__all__ = [name for name in dir(_impl) if not name.startswith("_")]

for _name in __all__:
    globals()[_name] = getattr(_impl, _name)
