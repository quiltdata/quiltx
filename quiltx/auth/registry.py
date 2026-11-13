"""Out-of-band catalog auth: bootstrap a qk_... API key from username/password.

This module is the only place quiltx talks U/P to a catalog. It composes
three existing endpoints, resolved against the **registry** URL the
catalog advertises in its ``/config.json`` (a typical deployment serves
the SPA from one DNS name and the registry API from another):

  1. POST <registry>/api/login       {username, password} -> {refresh_token}
  2. POST <registry>/api/token       {refresh_token}      -> {access_token}
  3. POST <registry>/graphql         apiKeyCreate         -> qk_... secret

The resulting qk_... is what every other quiltx command consumes via the
keyring. The refresh_token is intentionally NOT persisted — quiltx left
the refresh-token model behind in §8.6.

No quilt3 imports. No global state read or written.
"""

from __future__ import annotations

import json
import os
import os.path
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from quiltx.auth import _native


class CatalogAuthError(RuntimeError):
    """Raised on any unrecoverable failure during U/P -> qk_ bootstrap."""


def _default_ssl_context() -> ssl.SSLContext | None:
    """Honour SSL_CERT_FILE / REQUESTS_CA_BUNDLE if set."""
    ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle and os.path.isfile(ca_bundle):
        return ssl.create_default_context(cafile=ca_bundle)
    return None


def _get_json(url: str) -> dict[str, Any]:
    """GET *url* and return the parsed JSON body.

    Used to read ``<catalog>/config.json`` so we can resolve the registry
    URL where the auth API actually lives.
    """
    req = urllib.request.Request(url, method="GET")
    context = _default_ssl_context()
    kwargs: dict[str, Any] = {}
    if context is not None:
        kwargs["context"] = context
    try:
        with urllib.request.urlopen(req, **kwargs) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise CatalogAuthError(
            f"Request to {url} failed ({exc.code}): {body.strip()}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CatalogAuthError(f"Could not reach {url}: {exc.reason}") from exc


def resolve_registry_url(catalog_url: str) -> str:
    """Resolve the registry API base URL for *catalog_url*.

    Reads ``registryUrl`` from ``<catalog_url>/config.json``. The catalog
    DNS name typically serves only the SPA; the registry (which actually
    answers ``/api/login``, ``/api/token``, ``/graphql``) lives at a
    separate host advertised by the catalog config. If config.json has no
    ``registryUrl`` field, fall back to the catalog URL itself (covers
    single-host dev setups).
    """
    return _native.resolve_registry_url(catalog_url)


def _post_json(
    url: str,
    payload: dict[str, Any],
    *,
    bearer: str | None = None,
) -> dict[str, Any]:
    """POST JSON to *url* and return the parsed response body.

    HTTP errors are surfaced as CatalogAuthError with the response body so
    callers can show the catalog's own error text (e.g. "SSO is required").
    """
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    context = _default_ssl_context()
    kwargs: dict[str, Any] = {}
    if context is not None:
        kwargs["context"] = context
    try:
        with urllib.request.urlopen(req, **kwargs) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise CatalogAuthError(
            f"Auth request to {url} failed ({exc.code}): {body.strip()}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CatalogAuthError(f"Could not reach {url}: {exc.reason}") from exc


def _post_form(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST a form-urlencoded body to *url* and return the parsed JSON response.

    The catalog registry's ``/api/token`` endpoint expects
    ``application/x-www-form-urlencoded`` and rejects JSON bodies with a
    generic 400 — the JSON path used by ``_post_json`` does not work here.
    """
    data = urllib.parse.urlencode(payload).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    context = _default_ssl_context()
    kwargs: dict[str, Any] = {}
    if context is not None:
        kwargs["context"] = context
    try:
        with urllib.request.urlopen(req, **kwargs) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise CatalogAuthError(
            f"Auth request to {url} failed ({exc.code}): {body.strip()}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CatalogAuthError(f"Could not reach {url}: {exc.reason}") from exc


def acquire_refresh_token(registry_url: str, username: str, password: str) -> str:
    """POST {username, password} to <registry_url>/api/login.

    Raises CatalogAuthError on HTTP error (e.g. SSO-only catalog rejects U/P
    with a body like ``"SSO is required for this catalog"``) or if the
    response is missing a refresh_token.
    """
    return _native.acquire_refresh_token(registry_url, username, password)


def exchange_refresh_token_for_access_token(
    registry_url: str, refresh_token: str
) -> str:
    """Trade the short-lived refresh_token for an access_token.

    The access_token is what we feed to the GraphQL mutation that mints the
    long-lived qk_... API key. Neither token is persisted.
    """
    return _native.exchange_refresh_token_for_access_token(registry_url, refresh_token)


def create_api_key(
    registry_url: str,
    access_token: str,
    *,
    name: str,
    expires_in_days: int,
) -> dict[str, Any]:
    """Mint a long-lived qk_... API key via GraphQL.

    Returns a dict with at least ``secret`` (the qk_...), plus echoed
    ``name`` and ``expires_at`` from the catalog response. Raises
    CatalogAuthError on any non-success path (transport, GraphQL errors,
    InvalidInput).
    """
    return _native.create_api_key(
        registry_url, access_token, str(name), int(expires_in_days)
    )


def validate_api_key(catalog_url: str, api_key: str) -> None:
    """Round-trip the catalog with *api_key* to confirm it is accepted.

    Resolves the registry URL from ``<catalog_url>/config.json``, then
    runs a minimal authenticated GraphQL query against it. Returns on
    success; raises CatalogAuthError on transport failure, on a 401/403
    from the catalog, or on any GraphQL ``errors`` payload.
    """
    # Call the Python ``resolve_registry_url`` so tests can patch it.
    registry_url = resolve_registry_url(catalog_url)
    _native.validate_api_key(registry_url, api_key)


def bootstrap_api_key(
    catalog_url: str,
    *,
    username: str,
    password: str,
    name: str,
    expires_in_days: int,
) -> dict[str, Any]:
    """Compose login -> token -> apiKeyCreate. Returns the create_api_key dict.

    The intermediate refresh_token and access_token are not retained beyond
    this call; only the qk_... ``secret`` (and its metadata) leaves.
    """
    registry_url = resolve_registry_url(catalog_url)
    refresh_token = acquire_refresh_token(registry_url, username, password)
    access_token = exchange_refresh_token_for_access_token(registry_url, refresh_token)
    return create_api_key(
        registry_url, access_token, name=name, expires_in_days=expires_in_days
    )


def bootstrap_api_key_from_refresh_token(
    catalog_url: str,
    *,
    refresh_token: str,
    name: str,
    expires_in_days: int,
) -> dict[str, Any]:
    """Mint a qk_... API key from an already-acquired refresh_token.

    Used by the browser-based login flow: the user authenticates via SSO in
    a browser tab opened at ``<registry>/login`` and pastes back the code
    that page displays — that code IS the refresh_token.
    """
    registry_url = resolve_registry_url(catalog_url)
    access_token = exchange_refresh_token_for_access_token(registry_url, refresh_token)
    return create_api_key(
        registry_url, access_token, name=name, expires_in_days=expires_in_days
    )


def open_browser(url: str) -> bool:
    """Open *url* in the user's default browser. Returns True on success."""
    import webbrowser

    try:
        return webbrowser.open(url, new=1, autoraise=True)
    except Exception:
        return False


def browser_login_url(catalog_url: str) -> str:
    """Return the registry's web login URL (SSO entry + paste-back code page)."""
    return resolve_registry_url(catalog_url).rstrip("/") + "/login"
