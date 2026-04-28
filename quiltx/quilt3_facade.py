"""Thin passthrough facade over the quilt3 runtime surface.

All code in quiltx/ that needs to call quilt3 at runtime should import from
here instead of importing quilt3 directly. This makes the quilt3 boundary
explicit and easy to stub in tests.

The only permitted direct quilt3 import outside this module is the type-only
``from quilt3.admin.types import Permission`` in acl.py.

Implementation note: every function uses a local ``import quilt3`` so that
test monkeypatches that replace ``sys.modules["quilt3"]`` take effect
correctly, matching the pattern used before this facade existed.

Threading note: ``_QUILT3_LOCK`` serialises the set_global_config +
login_with_token + immediate quilt3 call sequence. This is a tripwire against
accidental reentrancy (two Catalog admin operations interleaving in one call
stack) — not a multi-thread feature.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Mapping

# Lock held during the bind-and-call sequence in Catalog.ensure_auth / admin.
# See §4.4 in the spec.
_QUILT3_LOCK = threading.Lock()


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


def login_with_token(refresh_token: str) -> None:
    """Exchange a refresh token for an access token and bind quilt3's session.

    Calls ``quilt3.session.login_with_token(refresh_token)``.
    Must be called after ``set_global_config`` so quilt3 knows which registry
    URL to key the auth.json entry under.
    """
    from quilt3.session import login_with_token as _login_with_token

    _login_with_token(refresh_token)


def default_boto3_session() -> object:
    from quilt3.session import get_boto3_session

    return get_boto3_session()


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
