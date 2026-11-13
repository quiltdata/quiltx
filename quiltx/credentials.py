"""Backward-compatible alias for :mod:`quiltx.auth.store`.

The credential store moved into the ``quiltx.auth`` subpackage. This module
*is* that module (not a copy), so existing imports and monkeypatches that name
``quiltx.credentials`` keep working. New code should use ``quiltx.auth.store``.
"""

import sys

from quiltx.auth import store as _store

sys.modules[__name__] = _store
