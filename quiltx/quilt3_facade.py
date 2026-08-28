"""Thin passthrough facade over the quilt3 runtime surface.

All code in quiltx/ that needs to call quilt3 at runtime should import from
here instead of importing quilt3 directly. This makes the quilt3 boundary
explicit and easy to stub in tests.

The only permitted direct quilt3 import outside this module is the type-only
``from quilt3.admin.types import Permission`` in acl.py.

Implementation note: every function uses a local ``import quilt3`` so that
test monkeypatches that replace ``sys.modules["quilt3"]`` take effect
correctly, matching the pattern used before this facade existed.

Registry selection uses quilt3's supported context-local resolver API. API
keys are passed to quilt3 with the resolved registry URL explicitly, so no
process-wide monkey-patch or quiltx-side synchronization is required.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

# Cache of catalog_url -> registry_url, populated lazily from
# <catalog>/config.json. Catalog and registry hosts may differ, and repeated
# auth/admin calls should not refetch config.json.
_REGISTRY_URL_CACHE: dict[str, str] = {}


def _resolve_registry_for_active_catalog(catalog_url: str) -> str:
    """Map *catalog_url* to its registry URL via config.json (cached).

    Catalog DNS typically serves only the SPA; the registry API lives at
    a separate host advertised by ``<catalog>/config.json``. If lookup
    fails (e.g. localhost dev stack with no config.json or no
    registryUrl), fall back to the catalog URL itself.
    """
    cached = _REGISTRY_URL_CACHE.get(catalog_url)
    if cached is not None:
        return cached
    from quiltx.quilt_auth import CatalogAuthError, resolve_registry_url

    try:
        resolved = resolve_registry_url(catalog_url)
    except CatalogAuthError:
        resolved = catalog_url.rstrip("/")
    _REGISTRY_URL_CACHE[catalog_url] = resolved
    return resolved


def bind_active_catalog(catalog_url: str):
    """Bind the catalog's registry URL through quilt3's supported API.

    Use ``Catalog`` as a context manager so the binding is cleaned up
    automatically. Direct callers are responsible for calling
    ``reset_active_catalog(token)`` when done.
    """
    from quilt3.session import set_registry_url_resolver

    registry_url = _resolve_registry_for_active_catalog(catalog_url)
    return set_registry_url_resolver(lambda: registry_url)


def reset_active_catalog(token) -> None:
    """Restore the quilt3 registry resolver replaced by a catalog binding."""
    from quilt3.session import reset_registry_url_resolver

    reset_registry_url_resolver(token)


@dataclass
class AdminClients:
    buckets: object
    policies: object
    roles: object
    sso_config: object
    users: object


def current_global_config() -> Mapping | None:
    import quilt3

    return quilt3.config()


def login_with_api_key(api_key: str, catalog_url: str) -> None:
    """Bind *api_key* to the registry advertised by *catalog_url*.

    Calls quilt3 with an explicit registry URL. Nothing is written to disk;
    quilt3 keeps the key in its per-registry in-memory key registry.
    """
    from quilt3.session import login_with_api_key as _login_with_api_key

    registry_url = _resolve_registry_for_active_catalog(catalog_url)
    _login_with_api_key(api_key, registry_url=registry_url)


def admin_modules() -> AdminClients:
    import quilt3.admin

    return AdminClients(
        buckets=quilt3.admin.buckets,
        policies=quilt3.admin.policies,
        roles=quilt3.admin.roles,
        sso_config=quilt3.admin.sso_config,
        users=quilt3.admin.users,
    )


def admin_graphql_client() -> Any:
    """Return quilt3's authenticated admin GraphQL client for the active catalog."""
    from quilt3.admin import util

    return util.get_client()


def admin_graphql(query: str, variables: Mapping[str, Any]) -> Mapping[str, Any]:
    """Execute a raw admin GraphQL document and return its ``data`` payload.

    Used for operations quilt3 does not generate a typed method for — notably
    reading and re-submitting a bucket's complete configuration, which is how
    the catalog stack is asked to re-verify live bucket access with its own
    identity.
    """
    client = admin_graphql_client()
    response = client.execute(query=query, variables=dict(variables))
    return client.get_data(response)


def make_bucket(bucket_uri: str) -> object:
    """Return a quilt3.Bucket instance for the given s3:// URI."""
    import quilt3

    return quilt3.Bucket(bucket_uri)


class CatalogCredentialsError(RuntimeError):
    """Raised when registry-issued credentials for the active catalog are absent.

    Never fall back to the ambient AWS credential chain in this case: the
    resulting account ID would describe whatever profile happens to be
    configured locally, not the catalog's control account (issue #91).
    """


# botocore method name reported by quilt3.session.QuiltProvider.
QUILT_CREDENTIALS_METHOD = "quilt-registry"


def _mint_registry_credentials() -> dict[str, str]:
    """Fetch fresh STS credentials from the active catalog's registry.

    Uses quilt3's authenticated HTTP session (the API key bound by
    ``Catalog.ensure_auth``) against the registry selected through quilt3's
    supported context-local resolver. Nothing is written to disk, and no
    cached or ambient credential source can substitute for this call.
    """
    import quilt3.session

    registry_url = quilt3.session.get_registry_url()
    if not registry_url:
        raise CatalogCredentialsError("no active catalog registry URL")
    session = quilt3.session.get_session()
    response = session.get(f"{registry_url.rstrip('/')}/api/auth/get_credentials")
    payload = response.json()
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


def catalog_botocore_session() -> Any:
    """Return a botocore session backed only by registry-issued credentials.

    Raises ``CatalogCredentialsError`` when the active catalog will not mint
    credentials, or when the resolved credentials did not come from quilt3's
    ``QuiltProvider``.
    """
    import quilt3.session

    try:
        credentials = _mint_registry_credentials()
    except CatalogCredentialsError:
        raise
    except Exception as exc:  # transport, auth, or quilt3 failure
        raise CatalogCredentialsError(
            f"catalog registry did not issue credentials: {exc}"
        ) from exc

    botocore_session = quilt3.session.create_botocore_session(credentials=credentials)
    resolved = botocore_session.get_credentials()
    method = getattr(resolved, "method", None)
    if resolved is None or method != QUILT_CREDENTIALS_METHOD:
        raise CatalogCredentialsError(
            "refusing to use credentials from "
            f"{method or 'the ambient AWS credential chain'}: expected "
            f"quilt3's {QUILT_CREDENTIALS_METHOD} provider"
        )
    return botocore_session


def catalog_sts_account_id() -> str:
    """Return the AWS account ID behind the active catalog's minted credentials.

    Uses quilt3's registry-issued temporary credentials — available to any
    logged-in catalog user, no admin role required — and asks STS which
    account they belong to: the catalog stack's control account.

    Raises ``CatalogCredentialsError`` rather than answering for the local
    AWS profile when the catalog does not mint credentials.
    """
    botocore_session = catalog_botocore_session()
    sts_client = botocore_session.create_client("sts")
    return str(sts_client.get_caller_identity()["Account"])
