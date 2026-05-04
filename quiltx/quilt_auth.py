"""Out-of-band catalog auth: bootstrap a qk_... API key from username/password.

This module is the only place quiltx talks U/P to a catalog. It composes
three existing endpoints:

  1. POST <catalog_url>/api/login       {username, password} -> {refresh_token}
  2. POST <catalog_url>/api/token       {refresh_token}      -> {access_token}
  3. POST <catalog_url>/graphql         apiKeyCreate         -> qk_... secret

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
import urllib.request
from typing import Any


class CatalogAuthError(RuntimeError):
    """Raised on any unrecoverable failure during U/P -> qk_ bootstrap."""


def _default_ssl_context() -> ssl.SSLContext | None:
    """Honour SSL_CERT_FILE / REQUESTS_CA_BUNDLE if set."""
    ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle and os.path.isfile(ca_bundle):
        return ssl.create_default_context(cafile=ca_bundle)
    return None


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


def acquire_refresh_token(catalog_url: str, username: str, password: str) -> str:
    """POST {username, password} to <catalog_url>/api/login.

    Raises CatalogAuthError on HTTP error (e.g. SSO-only catalog rejects U/P
    with a body like ``"SSO is required for this catalog"``) or if the
    response is missing a refresh_token.
    """
    url = catalog_url.rstrip("/") + "/api/login"
    response = _post_json(url, {"username": username, "password": password})
    token = response.get("refresh_token")
    if not token:
        raise CatalogAuthError(
            f"No refresh_token in login response from {url}. "
            f"Response keys: {list(response.keys())}"
        )
    return str(token)


def exchange_refresh_token_for_access_token(
    catalog_url: str, refresh_token: str
) -> str:
    """Trade the short-lived refresh_token for an access_token.

    The access_token is what we feed to the GraphQL mutation that mints the
    long-lived qk_... API key. Neither token is persisted.
    """
    url = catalog_url.rstrip("/") + "/api/token"
    response = _post_json(url, {"refresh_token": refresh_token})
    access_token = response.get("access_token")
    if not access_token:
        raise CatalogAuthError(
            f"No access_token in token response from {url}. "
            f"Response keys: {list(response.keys())}"
        )
    return str(access_token)


_API_KEY_CREATE_MUTATION = """
mutation apiKeyCreate($input: APIKeyCreateInput!) {
  apiKeyCreate(input: $input) {
    __typename
    ... on APIKeyCreated {
      apiKey { id name expiresAt }
      secret
    }
    ... on InvalidInput {
      errors { path message name }
    }
  }
}
""".strip()


def create_api_key(
    catalog_url: str,
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
    url = catalog_url.rstrip("/") + "/graphql"
    payload = {
        "query": _API_KEY_CREATE_MUTATION,
        "operationName": "apiKeyCreate",
        "variables": {"input": {"name": name, "expiresInDays": int(expires_in_days)}},
    }
    response = _post_json(url, payload, bearer=access_token)
    if "errors" in response and response["errors"]:
        raise CatalogAuthError(f"GraphQL errors: {response['errors']}")
    data = response.get("data") or {}
    result = data.get("apiKeyCreate")
    if not result:
        raise CatalogAuthError(f"Unexpected GraphQL response from {url}: {response!r}")
    typename = result.get("__typename")
    if typename == "APIKeyCreated":
        secret = result.get("secret")
        if not secret:
            raise CatalogAuthError("apiKeyCreate succeeded but returned no secret")
        return {
            "secret": str(secret),
            "name": (result.get("apiKey") or {}).get("name") or name,
            "expires_at": (result.get("apiKey") or {}).get("expiresAt"),
        }
    if typename == "InvalidInput":
        raise CatalogAuthError(
            f"Catalog rejected apiKeyCreate input: {result.get('errors')}"
        )
    raise CatalogAuthError(
        f"Unexpected apiKeyCreate result type {typename!r}: {result!r}"
    )


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
    refresh_token = acquire_refresh_token(catalog_url, username, password)
    access_token = exchange_refresh_token_for_access_token(catalog_url, refresh_token)
    return create_api_key(
        catalog_url, access_token, name=name, expires_in_days=expires_in_days
    )
