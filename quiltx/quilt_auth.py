"""I/O layer for minting Quilt refresh tokens directly from the catalog.

quiltx talks to the catalog's own auth endpoint to acquire credentials,
without going through quilt3's browser flow.

This module has no quilt3 imports and writes no global state.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any


def _default_ssl_context() -> ssl.SSLContext | None:
    """Honour SSL_CERT_FILE / REQUESTS_CA_BUNDLE if set."""
    import os

    ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle and __import__("os.path", fromlist=["isfile"]).isfile(ca_bundle):
        return ssl.create_default_context(cafile=ca_bundle)
    return None


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST JSON payload to url, return parsed JSON response body."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    context = _default_ssl_context()
    kwargs: dict[str, Any] = {}
    if context is not None:
        kwargs["context"] = context
    try:
        with urllib.request.urlopen(req, **kwargs) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(
            f"Auth request to {url} failed ({exc.code}): {body}"
        ) from exc


def acquire_refresh_token(catalog_url: str, username: str, password: str) -> str:
    """POST {username, password} to <catalog_url>/api/login.

    Returns the refresh_token from the response.
    Raises RuntimeError on HTTP error or missing token.
    No quilt3 calls; no global state read or written.
    """
    url = catalog_url.rstrip("/") + "/api/login"
    response = _post_json(url, {"username": username, "password": password})
    token = response.get("refresh_token")
    if not token:
        raise RuntimeError(
            f"No refresh_token in login response from {url}. "
            f"Response keys: {list(response.keys())}"
        )
    return str(token)


def validate_refresh_token(catalog_url: str, refresh_token: str) -> bool:
    """Lightweight liveness probe: exchange refresh token for access token.

    Returns True if the token is still valid, False otherwise.
    Never raises — failures are treated as invalid tokens.
    """
    url = catalog_url.rstrip("/") + "/api/token"
    try:
        _post_json(url, {"refresh_token": refresh_token})
        return True
    except Exception:
        return False
