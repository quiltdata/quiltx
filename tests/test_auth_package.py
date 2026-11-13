"""The quiltx.auth subpackage and its backward-compatible aliases."""

from __future__ import annotations

import importlib


def test_legacy_credentials_module_is_the_store_module() -> None:
    from quiltx import credentials as legacy
    from quiltx.auth import store

    assert legacy is store
    assert importlib.import_module("quiltx.credentials") is store


def test_legacy_quilt_auth_module_is_the_registry_module() -> None:
    from quiltx import quilt_auth as legacy
    from quiltx.auth import registry

    assert legacy is registry
    assert importlib.import_module("quiltx.quilt_auth") is registry


def test_patching_a_legacy_name_reaches_the_real_module(monkeypatch) -> None:
    from quiltx import credentials as legacy
    from quiltx.auth import store

    monkeypatch.setattr(legacy, "_keyring_available", lambda: False)

    assert store._keyring_available() is False


def test_package_exports_the_resolver_surface() -> None:
    from quiltx import auth
    from quiltx.auth import resolve

    for name in auth.__all__:
        assert getattr(auth, name) is getattr(resolve, name)
    assert {"resolve_cli", "resolve_api", "CredentialError"} <= set(auth.__all__)


def test_facade_re_exports_registry_credentials_api() -> None:
    from quiltx import quilt3_facade
    from quiltx.auth import session

    assert quilt3_facade.CatalogCredentialsError is session.CatalogCredentialsError
    assert quilt3_facade.catalog_sts_account_id is session.catalog_sts_account_id
    assert quilt3_facade.QUILT_CREDENTIALS_METHOD == session.QUILT_CREDENTIALS_METHOD


def test_alias_names_are_visible_to_type_checkers() -> None:
    # mypy checks this file: these imports resolve through the alias modules'
    # TYPE_CHECKING star-imports, and at runtime to the real objects.
    from quiltx.auth import registry, store
    from quiltx.credentials import get
    from quiltx.quilt_auth import CatalogAuthError

    assert get is store.get
    assert CatalogAuthError is registry.CatalogAuthError


def test_patching_the_package_name_is_what_callers_see(monkeypatch) -> None:
    from quiltx import auth
    from quiltx.auth import resolve

    sentinel = object()
    monkeypatch.setattr(auth, "resolve_cli", sentinel)
    from quiltx.auth import resolve_cli  # what Catalog.ensure_auth does at call time

    assert resolve_cli is sentinel

    monkeypatch.undo()
    monkeypatch.setattr(resolve, "resolve_cli", sentinel)
    from quiltx.auth import resolve_cli as seen_by_callers

    assert (
        seen_by_callers is not sentinel
    )  # patching the submodule attribute is not enough
