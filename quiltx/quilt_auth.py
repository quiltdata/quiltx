"""Backward-compatible alias for :mod:`quiltx.auth.registry`.

The catalog registry client moved into the ``quiltx.auth`` subpackage. This
module *is* that module (not a copy), so existing imports and monkeypatches that
name ``quiltx.quilt_auth`` keep working. New code should use
``quiltx.auth.registry``.
"""

import sys
from typing import TYPE_CHECKING

from quiltx.auth import registry as _registry

if TYPE_CHECKING:
    # For type checkers only: at runtime the sys.modules swap below makes this
    # module the real one. (Underscore names are not star-exported; import
    # them from quiltx.auth.registry.)
    from quiltx.auth.registry import *  # noqa: F401,F403

sys.modules[__name__] = _registry
