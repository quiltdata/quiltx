"""Backward-compatible alias for :mod:`quiltx.auth.store`.

The credential store moved into the ``quiltx.auth`` subpackage. This module
*is* that module (not a copy), so existing imports and monkeypatches that name
``quiltx.credentials`` keep working. New code should use ``quiltx.auth.store``.
"""

import sys
from typing import TYPE_CHECKING

from quiltx.auth import store as _store

if TYPE_CHECKING:
    # For type checkers only: at runtime the sys.modules swap below makes this
    # module the real one. (Underscore names are not star-exported; import
    # them from quiltx.auth.store.)
    from quiltx.auth.store import *  # noqa: F401,F403

sys.modules[__name__] = _store
