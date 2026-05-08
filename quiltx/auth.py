"""API-key resolver for quiltx.

Returns ``(api_key, source)`` given a catalog and context.

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

from quiltx import credentials

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

    # 1. Flag
    api_key_flag = getattr(args, "api_key", None)
    if api_key_flag:
        return ResolvedCredentials(api_key_flag, "flag")

    # 2. Env var
    env_key = os.environ.get("QUILTX_API_KEY")
    if env_key:
        return ResolvedCredentials(env_key, "env")

    # 3. Keyring (skipped on retry after auth failure)
    if not skip_keyring:
        stored = credentials.get(dns)
        if stored is not None:
            return ResolvedCredentials(stored["api_key"], "keyring")

    # 4. Interactive auth flow
    if _no_prompt_active(args) or not sys.stdin.isatty():
        raise CredentialError(
            f"No API key available for {dns}. "
            "Provide --api-key, set QUILTX_API_KEY, "
            f"or run `quiltx catalog api-key --catalog {dns}` interactively."
        )

    if skip_keyring:
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

    # 1. Constructor kwarg
    if api_key:
        return ResolvedCredentials(api_key, "flag")

    # 2. Env var
    env_key = os.environ.get("QUILTX_API_KEY")
    if env_key:
        return ResolvedCredentials(env_key, "env")

    # 3. Keyring
    if not skip_keyring:
        stored = credentials.get(dns)
        if stored is not None:
            return ResolvedCredentials(stored["api_key"], "keyring")

    raise CredentialError(
        f"No API key available for {dns}. "
        "Pass api_key=... to Catalog.from_dns, set QUILTX_API_KEY, "
        "or run a CLI command first to store one."
    )
