"""Shared helpers for quiltx tools."""

from __future__ import annotations

from typing import Any

__all__ = ["__version__", "configured_catalog"]
__version__ = "0.1.0"


def configured_catalog(*catalog_url: str, **config_values: Any):
    """Configure quilt3 and return a Catalog."""
    import quilt3

    quilt3.config(*catalog_url, **config_values)
    return quilt3.Catalog()
