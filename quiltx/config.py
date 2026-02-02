"""Configuration helpers for quiltx."""

from __future__ import annotations

from typing import Any


def configured_catalog(*catalog_url: str, **config_values: Any):
    """Configure quilt3 and return the current config."""
    import quilt3

    return quilt3.config(*catalog_url, **config_values)
