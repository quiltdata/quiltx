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
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Mapping

# Lock held during the bind-and-call sequence in Catalog.ensure_auth / admin.
# See §4.4 in the spec.
_QUILT3_LOCK = threading.Lock()

# Per spec [05 §5]: rebind quilt3.session.get_registry_url to return the
# active catalog URL without writing config.yml. The ContextVar makes this
# thread/async-safe; the monkey-patch is installed lazily on first bind().
_ACTIVE_CATALOG_URL: ContextVar[str | None] = ContextVar(
    "quiltx_active_catalog_url", default=None
)
_PATCH_INSTALLED = False
_PATCH_LOCK = threading.Lock()


def _install_registry_url_patch() -> None:
    """Replace ``quilt3.session.get_registry_url`` with a ContextVar-aware version.

    Idempotent. Called once on first bind_active_catalog() / login_with_api_key()
    invocation. The original function is preserved as a fallback for when no
    catalog is bound (e.g. quilt3.config()-driven flows).
    """
    global _PATCH_INSTALLED
    if _PATCH_INSTALLED:
        return
    with _PATCH_LOCK:
        if _PATCH_INSTALLED:
            return
        from quilt3 import session as _session

        original = _session.get_registry_url

        def get_registry_url() -> str:
            override = _ACTIVE_CATALOG_URL.get()
            if override is not None:
                return override
            return original()

        _session.get_registry_url = get_registry_url
        _PATCH_INSTALLED = True


def bind_active_catalog(catalog_url: str):
    """Install a process-local override so quilt3 sees *catalog_url*.

    Returns the ContextVar token from the caller can use to reset() the
    binding (e.g. in tests or nested operations). Production code generally
    leaves the binding in place for the lifetime of the command.
    """
    _install_registry_url_patch()
    return _ACTIVE_CATALOG_URL.set(catalog_url)


def reset_active_catalog(token) -> None:
    """Reset the ContextVar binding to its previous state."""
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


def set_global_config(url: str, **kw: object) -> object:
    # TODO: remove after §4 lands — once per-instance auth is live, no code
    # path writes the global config.
    import quilt3

    return quilt3.config(url, **kw)


def login_global(url: str | None = None) -> None:
    import quilt3

    if url is None:
        quilt3.login()
    else:
        quilt3.login(url)


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
