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
  ``quiltx._core`` extension.

``quiltx.credentials`` and ``quiltx.quilt_auth`` remain as aliases of
``store`` and ``registry`` for external importers; new code should import from
this package.
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
