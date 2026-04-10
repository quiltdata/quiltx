"""Shared helpers for quiltx tools."""

from __future__ import annotations

from quiltx._version import __version__ as __version__
from quiltx.config import (
    auto_login as auto_login,
    get_catalog_config as get_catalog_config,
    get_catalog_region as get_catalog_region,
    get_catalog_url as get_catalog_url,
    set_catalog_url as set_catalog_url,
)

__all__ = [
    "__version__",
    "auto_login",
    "get_catalog_config",
    "get_catalog_region",
    "get_catalog_url",
    "set_catalog_url",
]
