"""General utility functions for quiltx."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse


def get_bucket_region(bucket_name: str, s3_client: Any = None) -> str:
    """Get the AWS region of an S3 bucket.

    Args:
        bucket_name: Name of the S3 bucket
        s3_client: Optional boto3 S3 client (creates one if not provided)

    Returns:
        AWS region string (e.g., "us-east-1", "us-west-2")

    Note:
        S3's get_bucket_location API returns None for us-east-1 buckets,
        which we normalize to "us-east-1".
    """
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    response = s3_client.get_bucket_location(Bucket=bucket_name)
    # get_bucket_location returns None for us-east-1
    location = response.get("LocationConstraint")
    return location if location else "us-east-1"


def normalize_url(url: str) -> str:
    """Normalize a URL to a canonical form.

    Args:
        url: URL string to normalize (e.g., "https://example.com/path/")

    Returns:
        Normalized URL with lowercase scheme/hostname and no trailing slashes

    Examples:
        >>> normalize_url("HTTPS://Example.COM/path/")
        'https://example.com/path'
        >>> normalize_url("example.com")
        'example.com'
    """
    url = url.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        normalized = urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/"),
                "",
                "",
                "",
            )
        )
        return normalized.rstrip("/")
    return url


def get_hostname(url: str) -> str:
    """Extract hostname/DNS name from a URL or hostname string.

    Args:
        url: URL or hostname string (e.g., "https://example.com/path" or "example.com")

    Returns:
        Lowercase hostname/DNS name

    Examples:
        >>> get_hostname("https://example.com/path")
        'example.com'
        >>> get_hostname("EXAMPLE.COM")
        'example.com'
    """
    value = url.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.hostname.lower() if parsed.hostname else value.lower()
    return value.lower()
