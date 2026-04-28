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
    from quiltx.quilt3_facade import current_global_config

    config = current_global_config()
    if not config:
        raise ValueError(
            "No Quilt catalog configured. Run 'quiltx config <url>' first."
        )
    return dict(config)


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


def get_catalog_region() -> str:
    """Get the AWS region from the current quilt3 configuration.

    Returns:
        The region from the configured catalog

    Raises:
        ValueError: If no catalog is configured or region is missing
    """
    config = get_catalog_config()
    region = config.get("region")
    if not region:
        raise ValueError("region not found in Quilt config")
    return str(region)


def normalize_catalog_url(catalog_url: str) -> str:
    """Ensure catalog_url has a scheme, defaulting to https://."""
    if "://" not in catalog_url:
        catalog_url = f"https://{catalog_url}"
    return catalog_url.rstrip("/")


def set_catalog_url(catalog_url: str, **config_values: Any) -> dict[str, Any]:
    """Set the catalog URL in quilt3 configuration.

    Args:
        catalog_url: The catalog URL to configure (e.g., "https://example.quiltdata.com")
        **config_values: Additional configuration values to set

    Returns:
        The updated configuration dictionary
    """
    from quiltx.quilt3_facade import set_global_config

    catalog_url = normalize_catalog_url(catalog_url)
    result = set_global_config(catalog_url, **config_values)
    return result if isinstance(result, dict) else {}
