"""Shared helpers for quiltx tools."""

from __future__ import annotations

from typing import Any

from quiltx import logs as logs
from quiltx import stack as stack

__all__ = ["__version__", "configured_catalog", "logs", "stack"]
__version__ = "0.1.2"


def configured_catalog(*catalog_url: str, **config_values: Any):
    """Configure quilt3 and return the current config."""
    import quilt3

    return quilt3.config(*catalog_url, **config_values)
