"""Thin passthrough facade over the quilt3 runtime surface.

All code in quiltx/ that needs to call quilt3 at runtime should import from
here instead of importing quilt3 directly. This makes the quilt3 boundary
explicit and easy to stub in tests.

The only permitted direct quilt3 import outside this module is the type-only
``from quilt3.admin.types import Permission`` in acl.py.

Implementation note: every function uses a local ``import quilt3`` so that
test monkeypatches that replace ``sys.modules["quilt3"]`` take effect
correctly, matching the pattern used before this facade existed.

Threading note: ``_QUILT3_LOCK`` serialises the registry-URL rebind +
login_with_api_key + immediate quilt3 call sequence. This is a tripwire
against accidental reentrancy (two Catalog admin operations interleaving
in one call stack) — not a multi-thread feature.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator, Mapping

# Lock held during the bind-and-call sequence in Catalog.ensure_auth / admin.
# See §4.4 in the spec.
_QUILT3_LOCK = threading.Lock()

# Per spec [05 §5]: rebind quilt3.session.get_registry_url to return the
# active catalog URL without writing config.yml. The ContextVar makes this
# task-safe; the monkey-patch is installed once at module import.
#
# Tracking issue for an upstream supported hook (which would let us delete
# this monkey-patch entirely): quiltdata/quilt#4878.
_ACTIVE_CATALOG_URL: ContextVar[str | None] = ContextVar(
    "quiltx_active_catalog_url", default=None
)

# Cache of catalog_url -> registry_url, populated lazily from
# <catalog>/config.json. Quilt3 calls get_registry_url repeatedly, and we
# don't want to refetch config.json on every call.
_REGISTRY_URL_CACHE: dict[str, str] = {}
_PATCH_INSTALLED = False


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


def _install_registry_url_patch() -> None:
    global _PATCH_INSTALLED
    if _PATCH_INSTALLED:
        return
    try:
        from quilt3 import session as _session
    except ImportError:
        # Some tests and bootstrap paths only need quilt3.config(). Defer the
        # session patch until a real quilt3 runtime is importable.
        return

    original = _session.get_registry_url

    def get_registry_url() -> str:
        override = _ACTIVE_CATALOG_URL.get()
        if override is not None:
            return _resolve_registry_for_active_catalog(override)
        return original()

    _session.get_registry_url = get_registry_url
    _PATCH_INSTALLED = True


_install_registry_url_patch()


def bind_active_catalog(catalog_url: str):
    """Set the active catalog URL for this task; return a reset token.

    Embedders should prefer ``use_catalog()`` or ``Catalog`` as a context
    manager so the binding is cleaned up automatically. Direct callers are
    responsible for calling ``reset_active_catalog(token)`` when done.
    """
    _install_registry_url_patch()
    return _ACTIVE_CATALOG_URL.set(catalog_url)


def reset_active_catalog(token) -> None:
    """Reset the ContextVar binding to its previous state."""
    _ACTIVE_CATALOG_URL.reset(token)


@contextmanager
def use_catalog(catalog_url: str) -> Iterator[None]:
    """Scope the active-catalog binding to a ``with`` block.

    Embedder-friendly wrapper around bind/reset. Inside the block, any
    quilt3 call that resolves ``session.get_registry_url`` sees
    *catalog_url*; on exit the previous binding is restored.
    """
    _install_registry_url_patch()
    token = _ACTIVE_CATALOG_URL.set(catalog_url)
    try:
        yield
    finally:
        _ACTIVE_CATALOG_URL.reset(token)


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


def login_with_api_key(api_key: str) -> None:
    """Bind quilt3's in-process session to *api_key*.

    Calls ``quilt3.session.login_with_api_key(api_key)``. Writes nothing to
    disk — the key lives in a module-level global inside quilt3.session.
    """
    from quilt3.session import login_with_api_key as _login_with_api_key

    _login_with_api_key(api_key)


def admin_modules() -> AdminClients:
    import quilt3.admin

    return AdminClients(
        buckets=quilt3.admin.buckets,
        policies=quilt3.admin.policies,
        roles=quilt3.admin.roles,
        sso_config=quilt3.admin.sso_config,
        users=quilt3.admin.users,
    )


def make_bucket(bucket_uri: str) -> object:
    """Return a quilt3.Bucket instance for the given s3:// URI."""
    import quilt3

    return quilt3.Bucket(bucket_uri)
