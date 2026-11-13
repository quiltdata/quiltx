"""Backward-compatible alias for :mod:`quiltx.auth.registry`.

The catalog registry client moved into the ``quiltx.auth`` subpackage. This
module *is* that module (not a copy), so existing imports and monkeypatches that
name ``quiltx.quilt_auth`` keep working. New code should use
``quiltx.auth.registry``.
"""

import sys

from quiltx.auth import registry as _registry

sys.modules[__name__] = _registry
