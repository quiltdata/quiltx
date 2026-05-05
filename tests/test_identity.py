"""Tests for quiltx.identity.normalize_dns."""

from __future__ import annotations

import pytest

from quiltx.identity import normalize_dns

# ---------------------------------------------------------------------------
# Acceptance cases from spec table
# ---------------------------------------------------------------------------


def test_bare_dns_name() -> None:
    assert normalize_dns("customer-acme.quilt.example") == "customer-acme.quilt.example"


def test_https_url() -> None:
    assert (
        normalize_dns("https://customer-acme.quilt.example")
        == "customer-acme.quilt.example"
    )


def test_https_url_trailing_slash() -> None:
    assert (
        normalize_dns("https://customer-acme.quilt.example/")
        == "customer-acme.quilt.example"
    )


def test_https_url_with_path() -> None:
    assert (
        normalize_dns("https://customer-acme.quilt.example/some/path")
        == "customer-acme.quilt.example"
    )


def test_uppercase_scheme_and_host() -> None:
    assert (
        normalize_dns("HTTPS://Customer-Acme.Quilt.Example")
        == "customer-acme.quilt.example"
    )


# ---------------------------------------------------------------------------
# Rejection cases
# ---------------------------------------------------------------------------


def test_rejects_http_url() -> None:
    with pytest.raises(ValueError, match="http:// is not supported"):
        normalize_dns("http://customer-acme.quilt.example")


def test_rejects_custom_port() -> None:
    with pytest.raises(ValueError, match="Custom ports are not supported"):
        normalize_dns("host:8443")


def test_rejects_custom_port_in_url() -> None:
    with pytest.raises(ValueError, match="Custom ports are not supported"):
        normalize_dns("https://customer-acme.quilt.example:8443")


def test_rejects_ipv4_address() -> None:
    with pytest.raises(ValueError, match="IP-address identifiers are not supported"):
        normalize_dns("10.0.0.5")


def test_rejects_ipv4_in_url() -> None:
    with pytest.raises(ValueError, match="IP-address identifiers are not supported"):
        normalize_dns("https://10.0.0.5")


def test_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="required"):
        normalize_dns("")


def test_rejects_whitespace_only() -> None:
    with pytest.raises(ValueError, match="required"):
        normalize_dns("   ")


def test_insecure_accepts_localhost() -> None:
    assert normalize_dns("localhost", insecure=True) == "localhost"


def test_insecure_accepts_http_localhost() -> None:
    assert normalize_dns("http://localhost", insecure=True) == "localhost"


def test_insecure_accepts_http_localhost_trailing_slash() -> None:
    assert normalize_dns("http://localhost/", insecure=True) == "localhost"


def test_insecure_rejects_non_localhost() -> None:
    with pytest.raises(ValueError, match="--insecure is only supported for localhost"):
        normalize_dns("example.com", insecure=True)


def test_insecure_rejects_http_non_localhost() -> None:
    with pytest.raises(ValueError, match="http://"):
        normalize_dns("http://example.com", insecure=True)


def test_http_rejected_without_insecure() -> None:
    with pytest.raises(ValueError, match="http:// is not supported"):
        normalize_dns("http://localhost")


def test_is_localhost() -> None:
    from quiltx.identity import is_localhost

    assert is_localhost("localhost") is True
    assert is_localhost("LOCALHOST") is True
    assert is_localhost(" localhost ") is True
    assert is_localhost("127.0.0.1") is False
    assert is_localhost("foo.local") is False
    assert is_localhost("example.com") is False


def test_build_catalog_url_https_default() -> None:
    from quiltx.identity import build_catalog_url

    assert build_catalog_url("example.com") == "https://example.com"


def test_build_catalog_url_insecure_localhost() -> None:
    from quiltx.identity import build_catalog_url

    assert build_catalog_url("localhost", insecure=True) == "http://localhost"


def test_build_catalog_url_insecure_non_localhost_falls_back_to_https() -> None:
    """build_catalog_url itself does not validate; normalize_dns enforces the
    localhost-only rule. Defense-in-depth: even if a caller passes
    insecure=True for a non-localhost DNS, the URL stays https."""
    from quiltx.identity import build_catalog_url

    assert build_catalog_url("example.com", insecure=True) == "https://example.com"
