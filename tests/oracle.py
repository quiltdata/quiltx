"""The pre-Rust Python implementations, kept verbatim as the parity oracle.

``quiltx.identity.normalize_dns``, the credential-path / file-store / keyring
lookups in ``quiltx.auth.store``, the registry HTTP in
``quiltx.auth.registry``, the STS mint in
``quiltx.auth.session``, and the resolve ladder in
``quiltx.auth.resolve`` now call ``quiltx._core``. The functions here are the
Python they replaced, so ``tests/test_core_parity.py`` can run old and new on
the same inputs. Nothing under ``quiltx/`` imports this module.
"""

from __future__ import annotations

from typing import Any

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse
import ssl
import urllib.error
import urllib.parse
import urllib.request

from platformdirs import user_data_path

LOCALHOST = "localhost"


def is_localhost(dns: str) -> bool:
    """True if *dns* identifies the local machine for --insecure testing."""
    return dns.strip().lower() == LOCALHOST


def normalize_dns(value: str, *, insecure: bool = False) -> str:
    """Normalize a catalog identifier to a bare DNS name.

    Accepts a plain DNS name or an https:// URL and returns the lowercase
    hostname with no scheme, path, query, or trailing slash.

    Args:
        value: DNS name or https:// URL for a Quilt catalog.
        insecure: When True, also accept ``http://localhost`` for local
            catalog testing. Any other use of http:// or any non-localhost
            target with insecure=True is still rejected.

    Returns:
        Lowercase hostname, e.g. ``"customer-acme.quilt.example"``.

    Raises:
        ValueError: For http://, custom ports, IP literals, or empty input.
            (insecure=True relaxes only the http://localhost case.)
    """
    value = value.strip()
    if not value:
        raise ValueError("catalog DNS name is required")

    # Reject http:// explicitly before urlparse interprets it.
    # Exception: --insecure permits http://localhost (and bare localhost) for
    # local catalog testing; that branch is taken below after host extraction.
    lowered = value.lower()
    http_prefix = lowered.startswith("http://")
    if http_prefix and not insecure:
        raise ValueError(
            "http:// is not supported. Use https:// or pass the DNS name directly."
        )

    # Strip https:// if present so urlparse can give us a clean netloc
    if "://" in value:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "http"}:
            raise ValueError(
                "http:// is not supported. Use https:// or pass the DNS name directly."
            )
        host = parsed.hostname or ""
        port = parsed.port
        if scheme == "http" and not (insecure and is_localhost(host)):
            raise ValueError("http:// is only supported with --insecure for localhost.")
    else:
        # Plain hostname — no scheme; urlparse won't split netloc correctly
        # so extract the host manually before any colon
        host_part = value.split("/")[0]  # strip any accidental path
        if ":" in host_part:
            host = host_part.split(":")[0]
            port = int(host_part.split(":")[1]) if host_part.split(":")[1] else None
        else:
            host = host_part
            port = None

    host = host.lower()

    if not host:
        raise ValueError("catalog DNS name is required")

    # Reject custom ports
    if port is not None:
        raise ValueError("Custom ports are not supported. Use the bare DNS name.")

    # Reject IP literals (IPv4 and IPv6)
    if _is_ip_address(host):
        raise ValueError("IP-address identifiers are not supported. Use the DNS name.")

    # --insecure is a localhost-only escape hatch.
    if insecure and not is_localhost(host):
        raise ValueError(
            "--insecure is only supported for localhost; "
            f"refusing to use insecure transport for {host}."
        )

    return host


def _is_ip_address(host: str) -> bool:
    """Return True if host looks like an IPv4 or IPv6 address."""
    # IPv4: four dot-separated decimal octets
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return True
    # IPv6: contains colons (already stripped of brackets by urlparse)
    if ":" in host:
        return True
    return False


def fallback_path() -> Path:
    return user_data_path("quiltx") / "credentials.json"


def index_path() -> Path:
    return user_data_path("quiltx") / "credentials_index.json"


KEYRING_SERVICE = "quiltx"


def keyring_entry(dns: str) -> tuple[str, str]:
    """What ``keyring.get_password(...)`` was called with."""
    return (KEYRING_SERVICE, dns)


# ---------------------------------------------------------------------------
# File-backed store (copied from quiltx.auth.store at 0.24.0, with the path
# taken as an argument instead of going through _fallback_path / _index_path)
# ---------------------------------------------------------------------------


def read_fallback(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def write_fallback(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Tighten parent dir mode in case it pre-existed at a looser umask.
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    payload = json.dumps(data, indent=2).encode("utf-8")
    # Open with mode 0o600 from the start so the secret never sits at the
    # default umask between create and chmod (TOCTOU window on shared hosts).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    # If the file pre-existed at looser perms (older quiltx), tighten it now.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_index(path: Path) -> list:
    if not path.exists():
        return []
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(result, list):
            return result
        return []
    except (json.JSONDecodeError, OSError):
        return []


def write_index(path: Path, entries: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Tighten parent dir mode in case it pre-existed at a looser umask:
    # the index leaks DNS names (not secrets), but on a shared host that is
    # still better kept private. Mirrors the pattern in _write_fallback.
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    path.write_text(json.dumps(entries), encoding="utf-8")


def add_to_index(path: Path, dns: str) -> None:
    entries = read_index(path)
    if dns not in entries:
        entries.append(dns)
        write_index(path, entries)


def remove_from_index(path: Path, dns: str) -> None:
    entries = read_index(path)
    if dns in entries:
        entries.remove(dns)
        write_index(path, entries)


def get_fallback(path: Path, dns: str) -> dict | None:
    data = read_fallback(path)
    entry = data.get(dns)
    if entry is None or "api_key" not in entry:
        return None
    return entry


def store_fallback(
    path: Path,
    dns: str,
    api_key: str,
    name: str | None = None,
    expires_at: int | None = None,
) -> None:
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("API key is empty")
    if not api_key.startswith("qk_"):
        raise ValueError(
            "API key does not start with 'qk_'. Quilt API keys begin with "
            "'qk_' — paste the secret shown after creating a key in the "
            "catalog UI under Profile → API Keys."
        )
    payload = {
        "api_key": api_key,
        "name": name,
        "expires_at": expires_at,
    }
    data = read_fallback(path)
    data[dns] = payload
    write_fallback(path, data)


def delete_fallback(path: Path, dns: str) -> None:
    data = read_fallback(path)
    if dns in data:
        data.pop(dns)
        write_fallback(path, data)


def list_fallback(path: Path) -> list[tuple[str, dict]]:
    results: list[tuple[str, dict]] = []
    data = read_fallback(path)
    for dns, entry in data.items():
        if "api_key" in entry:
            results.append((dns, entry))
    return results


# ---------------------------------------------------------------------------
# Keyring-backed store (copied from quiltx.auth.store at the #152 merge, with
# the keyring object, paths, and use_keyring flag taken as arguments)
# ---------------------------------------------------------------------------


def get(
    dns: str,
    *,
    use_keyring: bool,
    fallback_path: Path,
    backend: object | None = None,
) -> dict | None:
    if use_keyring:
        raw = backend.get_password(*keyring_entry(dns))  # type: ignore[union-attr]
        if raw is None:
            return None
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(entry, dict) or "api_key" not in entry:
            return None
        return entry
    return get_fallback(fallback_path, dns)


def store(
    dns: str,
    api_key: str,
    *,
    name: str | None = None,
    expires_at: int | None = None,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
    backend: object | None = None,
) -> None:
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("API key is empty")
    if not api_key.startswith("qk_"):
        raise ValueError(
            "API key does not start with 'qk_'. Quilt API keys begin with "
            "'qk_' — paste the secret shown after creating a key in the "
            "catalog UI under Profile → API Keys."
        )
    payload = {
        "api_key": api_key,
        "name": name,
        "expires_at": expires_at,
    }
    if use_keyring:
        backend.set_password(*keyring_entry(dns), json.dumps(payload))  # type: ignore[union-attr]
        add_to_index(index_path, dns)
    else:
        store_fallback(fallback_path, dns, api_key, name, expires_at)


def delete(
    dns: str,
    *,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
    backend: object | None = None,
) -> None:
    if use_keyring:
        import keyring.errors

        try:
            backend.delete_password(*keyring_entry(dns))  # type: ignore[union-attr]
        except keyring.errors.PasswordDeleteError:
            pass
        remove_from_index(index_path, dns)
    else:
        delete_fallback(fallback_path, dns)


def catalog_list(
    *,
    use_keyring: bool,
    fallback_path: Path,
    index_path: Path,
    backend: object | None = None,
) -> list[tuple[str, dict]]:
    if use_keyring:
        results: list[tuple[str, dict]] = []
        for dns in read_index(index_path):
            entry = get(
                dns, use_keyring=True, fallback_path=fallback_path, backend=backend
            )
            if entry is not None:
                results.append((dns, entry))
        return results
    return list_fallback(fallback_path)


# ---------------------------------------------------------------------------
# Registry HTTP (quiltx.auth.registry before the Rust port)
# ---------------------------------------------------------------------------

from quiltx.auth.registry import CatalogAuthError


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
    base = catalog_url.rstrip("/")
    config = _get_json(base + "/config.json")
    registry_url = config.get("registryUrl")
    if not registry_url:
        return base
    return str(registry_url).rstrip("/")


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
    url = registry_url.rstrip("/") + "/api/login"
    response = _post_json(url, {"username": username, "password": password})
    token = response.get("refresh_token")
    if not token:
        raise CatalogAuthError(
            f"No refresh_token in login response from {url}. "
            f"Response keys: {list(response.keys())}"
        )
    return str(token)


def exchange_refresh_token_for_access_token(
    registry_url: str, refresh_token: str
) -> str:
    """Trade the short-lived refresh_token for an access_token.

    The access_token is what we feed to the GraphQL mutation that mints the
    long-lived qk_... API key. Neither token is persisted.
    """
    url = registry_url.rstrip("/") + "/api/token"
    response = _post_form(url, {"refresh_token": refresh_token})
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
    url = registry_url.rstrip("/") + "/graphql"
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


_VALIDATE_QUERY = "query apiKeysList { apiKeysList(input: {}) { apiKeys { id } } }"


def validate_api_key(catalog_url: str, api_key: str) -> None:
    """Round-trip the catalog with *api_key* to confirm it is accepted.

    Resolves the registry URL from ``<catalog_url>/config.json``, then
    runs a minimal authenticated GraphQL query against it. Returns on
    success; raises CatalogAuthError on transport failure, on a 401/403
    from the catalog, or on any GraphQL ``errors`` payload.
    """
    registry_url = resolve_registry_url(catalog_url)
    url = registry_url + "/graphql"
    payload = {"query": _VALIDATE_QUERY, "operationName": "apiKeysList"}
    response = _post_json(url, payload, bearer=api_key)
    if response.get("errors"):
        raise CatalogAuthError(f"Catalog rejected API key: {response['errors']}")


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


from quiltx.auth.session import CatalogCredentialsError


def _sts_get_json(url: str) -> Any:
    """Placeholder the parity tests patch; the production helper is in session.py."""
    raise AssertionError(f"tests must patch oracle._sts_get_json, got {url}")


def mint_registry_credentials(registry_url: str) -> dict[str, Any]:
    """GET ``<registry_url>/api/auth/get_credentials`` and map the STS payload.

    The HTTP call and dict mapping from ``quiltx.auth.session._mint_registry_credentials``
    at the #154 merge, with the transport left injectable so the parity
    tests can use recorded responses (the quilt3 session lookup stays in
    the Python facade).
    """
    url = registry_url.rstrip("/") + "/api/auth/get_credentials"
    payload = _sts_get_json(url)
    try:
        return {
            "access_key": payload["AccessKeyId"],
            "secret_key": payload["SecretAccessKey"],
            "token": payload["SessionToken"],
            "expiry_time": payload["Expiration"],
        }
    except (KeyError, TypeError) as exc:
        raise CatalogCredentialsError(
            f"registry {registry_url} returned no usable credentials"
        ) from exc


from quiltx.auth.resolve import CredentialError as _CredentialError


def resolve_credentials(
    dns: str,
    provided: str | None,
    env_key: str | None,
    stored_key: str | None,
    skip_keyring: bool,
    allow_interactive: bool,
    mode: str,
) -> dict[str, Any]:
    """The non-interactive resolve ladder from ``quiltx.auth.resolve`` at the #155 merge."""
    if provided:
        return {"status": "found", "api_key": provided, "source": "flag"}
    if env_key:
        return {"status": "found", "api_key": env_key, "source": "env"}
    if not skip_keyring and stored_key is not None:
        return {"status": "found", "api_key": stored_key, "source": "keyring"}
    if mode == "cli" and allow_interactive:
        return {"status": "need_interactive", "rejected": skip_keyring}
    if mode == "cli":
        raise _CredentialError(
            f"No API key available for {dns}. "
            "Provide --api-key, set QUILTX_API_KEY, "
            f"or run `quiltx catalog api-key --catalog {dns}` interactively."
        )
    raise _CredentialError(
        f"No API key available for {dns}. "
        "Pass api_key=... to Catalog.from_dns, set QUILTX_API_KEY, "
        "or run a CLI command first to store one."
    )
