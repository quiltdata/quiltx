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
