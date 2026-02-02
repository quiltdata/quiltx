"""Shared helpers for quiltx tools."""

from __future__ import annotations

from quiltx._version import __version__ as __version__
from quiltx.config import configured_catalog as configured_catalog

__all__ = ["__version__", "configured_catalog"]
