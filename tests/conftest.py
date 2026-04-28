"""Shared pytest fixtures and factories for quiltx tests."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Mapping

from quiltx.stack import AdminClients, Catalog

_SENTINEL = object()


class _FakeCatalog(Catalog):
    """A Catalog subclass that returns a fixed payload for tests."""

    _test_payload: Mapping[str, Any] | None

    @property
    def payload(self) -> Mapping[str, Any] | None:
        return self._test_payload


def make_fake_catalog(
    catalog_name: str = "nightly.quilttest.com",
    *,
    authed: bool = True,
    payload: dict[str, Any] | None = None,
    buckets: Any = _SENTINEL,
    policies: Any = _SENTINEL,
    roles: Any = _SENTINEL,
    sso_config: Any = _SENTINEL,
    users: Any = _SENTINEL,
) -> Catalog:
    """Return a Catalog with stub admin, stub boto3_session, and no-op ensure_auth.

    When any of buckets/policies/roles/sso_config/users are provided, a
    pre-built AdminClients is injected so tests do not need quilt3 in
    sys.modules. If none are provided the catalog behaves like a normal
    Catalog and loads admin lazily from quilt3 (suitable for tests that
    separately monkeypatch sys.modules["quilt3.admin"]).

    Args:
        catalog_name: DNS name for the fake catalog.
        authed: Reserved; ensure_auth is always a no-op for now.
        payload: Optional fixed stack payload returned by catalog.payload.
        buckets/policies/roles/sso_config/users: Stub admin sub-modules.
            Providing any of these causes an AdminClients to be pre-injected.

    Returns:
        A Catalog instance suitable for unit tests.
    """
    has_admin_stubs = any(
        v is not _SENTINEL for v in (buckets, policies, roles, sso_config, users)
    )

    if payload is not None:
        cat: Catalog = _FakeCatalog(
            catalog_name=catalog_name,
            catalog_url=f"https://{catalog_name}",
            source="flag",
            auth_required=False,
        )
        object.__setattr__(cat, "_test_payload", payload)
    else:
        cat = Catalog(
            catalog_name=catalog_name,
            catalog_url=f"https://{catalog_name}",
            source="flag",
            auth_required=False,
        )

    if has_admin_stubs:
        admin = AdminClients(
            buckets=buckets if buckets is not _SENTINEL else SimpleNamespace(),
            policies=policies if policies is not _SENTINEL else SimpleNamespace(),
            roles=roles if roles is not _SENTINEL else SimpleNamespace(),
            sso_config=sso_config if sso_config is not _SENTINEL else SimpleNamespace(),
            users=users if users is not _SENTINEL else SimpleNamespace(),
        )
        object.__setattr__(cat, "_admin", admin)

    return cat
