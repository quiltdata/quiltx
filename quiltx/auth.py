"""Credential resolver for quiltx.

Returns ``(username, secret, source)`` given a catalog and context.

CLI ladder:
  1. --username / --password flags (must appear together)
  2. QUILTX_USERNAME / QUILTX_PASSWORD env vars (both or neither)
  3. keyring entry for catalog.catalog_name
  4. Interactive prompt (only if TTY + not --no-prompt + not QUILTX_NO_PROMPT)
  5. Error

API ladder (no CLI args, no TTY):
  1. Constructor kwargs (username/password passed to Catalog.from_dns)
  2. QUILTX_USERNAME / QUILTX_PASSWORD env vars
  3. keyring entry for catalog.catalog_name
  4. Error

``source`` is one of: "flag", "env", "keyring", "prompt".
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import TYPE_CHECKING, Literal, NamedTuple

from quiltx import credentials

if TYPE_CHECKING:
    from quiltx.stack import Catalog

CredentialSource = Literal["flag", "env", "keyring", "prompt"]


class ResolvedCredentials(NamedTuple):
    username: str
    secret: str
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


def resolve_cli(catalog: "Catalog", args: object | None = None) -> ResolvedCredentials:
    """Resolve credentials for a CLI invocation.

    ``args`` is the parsed argparse.Namespace (may be None).
    """
    dns = catalog.catalog_name

    # 1. Flags
    username_flag = getattr(args, "username", None)
    password_flag = getattr(args, "password", None)
    if username_flag and password_flag:
        return ResolvedCredentials(username_flag, password_flag, "flag")

    # 2. Env vars
    env_user = os.environ.get("QUILTX_USERNAME")
    env_pass = os.environ.get("QUILTX_PASSWORD")
    if env_user and env_pass:
        return ResolvedCredentials(env_user, env_pass, "env")

    # 3. Keyring
    stored = credentials.get(dns)
    if stored:
        return ResolvedCredentials(stored["username"], stored["secret"], "keyring")

    # 4. Interactive prompt
    if _no_prompt_active(args) or not sys.stdin.isatty():
        raise CredentialError(
            f"No credentials available for {dns}. "
            "Provide --username and --password, set QUILTX_USERNAME / QUILTX_PASSWORD, "
            "or run interactively to be prompted."
        )

    print(f"No stored credentials for {dns}.", file=sys.stderr)
    try:
        username = input("Username: ")
        secret = getpass.getpass("Password: ")
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        raise CredentialError(f"Authentication aborted for {dns}.")

    # Store for future runs
    credentials.set(dns, username, secret)
    return ResolvedCredentials(username, secret, "prompt")


def resolve_api(
    catalog: "Catalog",
    *,
    username: str | None = None,
    password: str | None = None,
) -> ResolvedCredentials:
    """Resolve credentials for an API (non-CLI) invocation.

    No prompting — API consumers use kwargs, env vars, or keyring.
    """
    dns = catalog.catalog_name

    # 1. Constructor kwargs
    if username and password:
        return ResolvedCredentials(username, password, "flag")

    # 2. Env vars
    env_user = os.environ.get("QUILTX_USERNAME")
    env_pass = os.environ.get("QUILTX_PASSWORD")
    if env_user and env_pass:
        return ResolvedCredentials(env_user, env_pass, "env")

    # 3. Keyring
    stored = credentials.get(dns)
    if stored:
        return ResolvedCredentials(stored["username"], stored["secret"], "keyring")

    raise CredentialError(
        f"No credentials available for {dns}. "
        "Pass username/password to Catalog.from_dns, set QUILTX_USERNAME / "
        "QUILTX_PASSWORD, or run a CLI command first to store credentials."
    )
