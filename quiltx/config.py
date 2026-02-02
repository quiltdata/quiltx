"""Configuration helpers for quiltx."""

from __future__ import annotations

from typing import Any


def get_catalog_config() -> dict[str, Any]:
    """Get the current quilt3 catalog configuration.

    Returns:
        Dictionary containing the catalog configuration from quilt3.config()

    Raises:
        ValueError: If no catalog is configured
    """
    import quilt3

    config = quilt3.config()
    if not config:
        raise ValueError(
            "No Quilt catalog configured. Run 'quiltx config <url>' first."
        )
    return config


def get_catalog_url() -> str:
    """Get the catalog URL from the current quilt3 configuration.

    Returns:
        The navigator_url from the configured catalog

    Raises:
        ValueError: If no catalog is configured or navigator_url is missing
    """
    config = get_catalog_config()
    url = config.get("navigator_url")
    if not url:
        raise ValueError("navigator_url not found in Quilt config")
    return str(url)


def set_catalog_url(catalog_url: str, **config_values: Any) -> dict[str, Any]:
    """Set the catalog URL in quilt3 configuration.

    Args:
        catalog_url: The catalog URL to configure (e.g., "https://example.quiltdata.com")
        **config_values: Additional configuration values to set

    Returns:
        The updated configuration dictionary
    """
    import quilt3

    return quilt3.config(catalog_url, **config_values)
