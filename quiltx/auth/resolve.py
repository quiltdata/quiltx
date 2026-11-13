"""API-key resolver for quiltx.

Returns ``(api_key, source)`` given a catalog and context. The ladder
decision runs in Rust (``quiltx._core.resolve_credentials``); this module
still reads flags, env, the store, and the TTY, and still runs
``mint_api_key`` for the interactive path.


CLI ladder ([05 §4]):
  1. --api-key flag
  2. QUILTX_API_KEY env var
  3. Keyring entry for catalog.catalog_name
  4. Interactive browser/SSO auth flow
  5. Error

API ladder (no CLI args, no TTY):
  1. Constructor kwarg (api_key passed to Catalog.from_dns)
  2. QUILTX_API_KEY env var
  3. Keyring entry for catalog.catalog_name
  4. Error

``source`` is one of: "flag", "env", "keyring", "auth-flow".

When ``skip_keyring=True`` is passed, step 3 is skipped — used by the retry
envelope in @catalog_command after an auth failure to force re-prompt
([06 §5 step 3]).
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Literal, NamedTuple

from quiltx.auth import store as credentials

if TYPE_CHECKING:
    from quiltx.stack import Catalog

CredentialSource = Literal["flag", "env", "keyring", "auth-flow"]


class ResolvedCredentials(NamedTuple):
    api_key: str
    source: CredentialSource


class CredentialError(Exception):
    """Raised when credentials cannot be resolved."""


def _no_prompt_active(args: object | None) -> bool:
    """Return True if interactive prompting should be suppressed."""
    if os.environ.get("QUILTX_NO_PROMPT"):
        return True
    if args is not None and getattr(args, "no_prompt", False):
        return True
    return False


def resolve_cli(
    catalog: "Catalog",
    args: object | None = None,
    *,
    skip_keyring: bool = False,
) -> ResolvedCredentials:
    """Resolve API key for a CLI invocation.

    ``args`` is the parsed argparse.Namespace (may be None).
    ``skip_keyring`` is set by the retry envelope after an auth failure.
    """
    dns = catalog.catalog_name
    from quiltx.auth import _native

    provided = getattr(args, "api_key", None)
    env_key = os.environ.get("QUILTX_API_KEY")
    stored_key = None
    if not skip_keyring:
        stored = credentials.get(dns)
        if stored is not None:
            stored_key = stored["api_key"]
    allow_interactive = not _no_prompt_active(args) and sys.stdin.isatty()
    result = _native.resolve_credentials(
        dns,
        provided,
        env_key,
        stored_key,
        skip_keyring,
        allow_interactive,
        "cli",
    )
    if result["status"] == "found":
        return ResolvedCredentials(result["api_key"], result["source"])

    if result["rejected"]:
        print(
            f"Stored API key for {dns} was rejected.",
            file=sys.stderr,
        )
    else:
        print(f"No stored API key for {dns}.", file=sys.stderr)

    from quiltx.tools.catalog import login as login_tool

    try:
        minted = login_tool.mint_api_key(
            catalog.catalog_url,
            dns,
            no_prompt=False,
        )
    except login_tool.LoginError as exc:
        raise CredentialError(str(exc)) from exc

    login_tool.print_stored_message(minted, dns)
    return ResolvedCredentials(minted.secret, "auth-flow")


def resolve_api(
    catalog: "Catalog",
    *,
    api_key: str | None = None,
    skip_keyring: bool = False,
) -> ResolvedCredentials:
    """Resolve API key for an API (non-CLI) invocation.

    No prompting — API consumers use kwargs, env vars, or keyring.
    """
    dns = catalog.catalog_name
    from quiltx.auth import _native

    env_key = os.environ.get("QUILTX_API_KEY")
    stored_key = None
    if not skip_keyring:
        stored = credentials.get(dns)
        if stored is not None:
            stored_key = stored["api_key"]
    result = _native.resolve_credentials(
        dns,
        api_key,
        env_key,
        stored_key,
        skip_keyring,
        False,
        "api",
    )
    return ResolvedCredentials(result["api_key"], result["source"])
