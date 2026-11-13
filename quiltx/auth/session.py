"""Registry-issued credentials for the active catalog.

Mints temporary STS credentials from the catalog's registry and builds a
botocore session that can only use them: the ambient AWS credential chain is
never an acceptable substitute (issue #91). This is the one ``quiltx.auth``
module that imports quilt3; every function does so locally, so tests that
replace ``sys.modules["quilt3"]`` take effect.

Moved out of ``quiltx.quilt3_facade`` unchanged; the facade re-exports these
names, so ``quilt3_facade.catalog_sts_account_id()`` and
``quilt3_facade.CatalogCredentialsError`` still work.
"""

from __future__ import annotations

from typing import Any


class CatalogCredentialsError(RuntimeError):
    """Raised when registry-issued credentials for the active catalog are absent.

    Never fall back to the ambient AWS credential chain in this case: the
    resulting account ID would describe whatever profile happens to be
    configured locally, not the catalog's control account (issue #91).
    """


# botocore method name reported by quilt3.session.QuiltProvider.
QUILT_CREDENTIALS_METHOD = "quilt-registry"


def _get_json(url: str) -> Any:
    """GET *url* through quilt3's authenticated catalog session.

    Kept in Python so tests that replace ``quilt3.session`` keep working,
    and so the API key bound by ``Catalog.ensure_auth`` is sent. Called
    from Rust when minting STS credentials.
    """
    import quilt3.session

    response = quilt3.session.get_session().get(url)
    return response.json()


def _mint_registry_credentials() -> dict[str, str]:
    """Fetch fresh STS credentials from the active catalog's registry.

    Uses quilt3's authenticated HTTP session (the API key bound by
    ``Catalog.ensure_auth``) against the registry selected through quilt3's
    supported context-local resolver. The GET and payload mapping run in
    Rust. Nothing is written to disk, and no cached or ambient credential
    source can substitute for this call.
    """
    from quiltx.auth import _native
    import quilt3.session

    registry_url = quilt3.session.get_registry_url()
    if not registry_url:
        raise CatalogCredentialsError("no active catalog registry URL")
    return _native.mint_registry_credentials(registry_url)


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
