"""Shared helpers for quiltx tools."""

from __future__ import annotations

from typing import Any

__all__ = ["__version__", "configured_catalog"]
__version__ = "0.1.0"


def configured_catalog(*args: Any, **kwargs: Any):
    """Return a configured quilt3 Catalog."""
    import quilt3

    quilt3.config(*args, **kwargs)
    return quilt3.Catalog()
