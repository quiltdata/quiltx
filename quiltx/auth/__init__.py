"""quiltx authentication: credential resolution, storage and catalog login.

This subpackage holds every piece of quiltx's catalog authentication, split by
responsibility. It was extracted from flat modules without changing behaviour:

* :mod:`quiltx.auth.resolve` - the API-key resolver (flag, env, keyring,
  interactive login). Its public names are re-exported here, so
  ``from quiltx.auth import resolve_cli`` keeps working.
* :mod:`quiltx.auth.store` - per-DNS credential storage (OS keyring, with a
  0600 file fallback). Formerly ``quiltx.credentials``.
* :mod:`quiltx.auth.registry` - out-of-band HTTP to a catalog's registry
  (login, token exchange, API-key creation, validation). Formerly
  ``quiltx.quilt_auth``. It never imports quilt3.
* :mod:`quiltx.auth.session` - registry-issued STS credentials and the
  botocore session built from them. The only auth module that imports quilt3.
* :mod:`quiltx.auth._native` - the single importer of the compiled
  ``quiltx._core`` extension, which is required: catalog-name normalization and the
  credential store's paths and keyring key come from it.

``quiltx.credentials`` and ``quiltx.quilt_auth`` remain as aliases of
``store`` and ``registry`` for external importers; new code should import from
this package.

Where to patch in tests
-----------------------

Callers look the resolver up on this package at call time
(``from quiltx.auth import resolve_cli`` inside ``Catalog.ensure_auth``), so to
stub it patch ``quiltx.auth.resolve_cli`` (or ``resolve_api``). Patching
``quiltx.auth.resolve.resolve_cli`` changes only the submodule's attribute and
callers do not see it. State the resolver reads is patched on the module that
owns it: ``quiltx.auth.store`` (``quiltx.credentials`` is the same module) and
``quiltx.auth.registry`` (``quiltx.quilt_auth``).
"""

from quiltx.auth.resolve import (
    CredentialError,
    CredentialSource,
    ResolvedCredentials,
    resolve_api,
    resolve_cli,
)

__all__ = [
    "CredentialError",
    "CredentialSource",
    "ResolvedCredentials",
    "resolve_api",
    "resolve_cli",
]
