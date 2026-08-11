"""quiltx catalog login: mint a qk_... API key.

Three paths (in priority order):

1. ``--api-key qk_...`` — paste an existing key; validated, then stored.
2. ``--username`` with a password from ``--password``, ``--password-stdin``,
   ``QUILTX_PASSWORD``, or an interactive prompt — POST to ``/api/login``, then
   exchange refresh_token → access_token → GraphQL ``apiKeyCreate``. SSO-only
   catalogs reject this path at ``/api/login``.
3. **Default** (interactive TTY, no ``--username``/``--api-key``,
   ``--no-browser`` not set): browser flow. Open ``<registry>/login`` in
   the user's browser, prompt them to paste back the code shown on that
   page (the refresh_token), then mint the API key. Works with any auth
   backend the catalog supports — including SSO.

Keys are stored by default. ``--no-store`` skips all credential persistence and
prints the key to stdout for use by automation.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import os
import socket
import sys

from dataclasses import dataclass

from quiltx import credentials, quilt_auth
from quiltx.cli_common import add_catalog_args
from quiltx.identity import build_catalog_url, normalize_dns


def _default_key_name() -> str:
    host = socket.gethostname().split(".", 1)[0] or "host"
    today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
    return f"quiltx-{host}-{today}"


def _parse_expires_at(value: object) -> int | None:
    """Parse an ISO-8601 ``expiresAt`` string from the catalog into epoch seconds."""
    if not isinstance(value, str) or not value:
        return None
    cleaned = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        dt = _dt.datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return int(dt.timestamp())


@dataclass(frozen=True)
class MintedApiKey:
    secret: str
    name: str
    expires_at: int | None


class LoginError(RuntimeError):
    """Raised when an interactive catalog login flow cannot complete."""


class LoginUsageError(LoginError):
    """Raised when the caller invoked the login flow with bad arguments."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog login",
        description=(
            "Mint a qk_... API key and store it in the system keyring. "
            "Default: open the catalog login page in a browser, then paste "
            "back the code shown there (works with SSO). Use --username for "
            "username/password bootstrap, or --api-key to store an existing "
            "key directly. Use --no-store for ephemeral automation."
        ),
    )
    add_catalog_args(parser, auth_required=True)
    parser.add_argument(
        "--username",
        help="Catalog admin username for U/P -> API-key bootstrap.",
    )
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument(
        "--password",
        help=(
            "Catalog admin password. INSECURE: visible in `ps`/process listings; "
            "prefer --password-stdin, QUILTX_PASSWORD, or an interactive prompt."
        ),
    )
    password_group.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the catalog admin password from the first line of stdin.",
    )
    parser.add_argument(
        "--no-store",
        action="store_true",
        help=(
            "Do not persist the API key; print only the key to stdout for "
            "capture as QUILTX_API_KEY."
        ),
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help=(
            "Disable the default browser-based login flow; fall back to "
            "interactive username/password prompts."
        ),
    )
    parser.add_argument(
        "--key-name",
        default=None,
        help=(
            "Name for the new API key (visible in `quiltx catalog list`). "
            "Defaults to quiltx-<host>-<YYYYMMDD>."
        ),
    )
    parser.add_argument(
        "--expires-in-days",
        type=int,
        default=365,
        help="API key expiration window in days (1-365). Default: 365.",
    )
    return parser


def _bootstrap_from_browser(
    catalog_url: str,
    dns: str,
    *,
    name: str,
    expires_in_days: int,
) -> dict[str, object]:
    """Browser-based login: open <registry>/login, prompt for paste-back code."""
    login_url = quilt_auth.browser_login_url(catalog_url)
    print(f"Opening {login_url} in your browser...")
    if not quilt_auth.open_browser(login_url):
        print(f"Could not open browser automatically. Please visit: {login_url}")
    print()
    try:
        refresh_token = input("Paste the code from the page here: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        raise LoginError(f"Authentication aborted for {dns}.")
    if not refresh_token:
        raise LoginError("No code provided.")
    try:
        return quilt_auth.bootstrap_api_key_from_refresh_token(
            catalog_url,
            refresh_token=refresh_token,
            name=name,
            expires_in_days=expires_in_days,
        )
    except quilt_auth.CatalogAuthError as exc:
        raise LoginError(f"Catalog rejected the code from {dns}: {exc}") from exc


def _bootstrap_from_credentials(
    catalog_url: str,
    *,
    username: str,
    password: str,
    name: str,
    expires_in_days: int,
) -> dict[str, object]:
    try:
        return quilt_auth.bootstrap_api_key(
            catalog_url,
            username=username,
            password=password,
            name=name,
            expires_in_days=expires_in_days,
        )
    except quilt_auth.CatalogAuthError as exc:
        # SSO-only catalogs reject /api/login; the catalog's body is in str(exc).
        message = str(exc)
        if "sso" in message.lower() or "401" in message:
            message = (
                f"{message}\nIf this catalog uses SSO, rerun without "
                "--no-browser to use the browser auth flow."
            )
        raise LoginError(message) from exc


def mint_api_key(
    catalog_url: str,
    dns: str,
    *,
    username: str | None = None,
    password: str | None = None,
    no_browser: bool = False,
    no_prompt: bool = False,
    key_name: str | None = None,
    expires_in_days: int = 365,
    store: bool = True,
) -> MintedApiKey:
    """Mint a catalog API key and optionally store it."""
    interactive = not no_prompt and sys.stdin.isatty()
    name = key_name or _default_key_name()

    if username is not None:
        resolved_password = password
        if resolved_password is None:
            if not interactive:
                raise LoginUsageError(
                    "A password is required when --username is set headlessly. "
                    "Use --password-stdin, QUILTX_PASSWORD, or --password."
                )
            try:
                resolved_password = getpass.getpass(f"Password for {username}@{dns}: ")
            except (KeyboardInterrupt, EOFError) as exc:
                print("\nAborted.", file=sys.stderr)
                raise LoginError(f"Authentication aborted for {dns}.") from exc
        result = _bootstrap_from_credentials(
            catalog_url,
            username=username,
            password=resolved_password,
            name=name,
            expires_in_days=expires_in_days,
        )
    elif interactive and not no_browser:
        result = _bootstrap_from_browser(
            catalog_url,
            dns,
            name=name,
            expires_in_days=expires_in_days,
        )
    else:
        if not interactive:
            raise LoginUsageError(
                "--username with a password source or interactive TTY is required "
                "(browser flow needs a TTY for paste-back)."
            )
        try:
            prompted_username = input(f"Username for {dns}: ").strip()
        except (KeyboardInterrupt, EOFError) as exc:
            print("\nAborted.", file=sys.stderr)
            raise LoginError(f"Authentication aborted for {dns}.") from exc
        if not prompted_username:
            raise LoginError("Username is required.")
        try:
            prompted_password = getpass.getpass(
                f"Password for {prompted_username}@{dns}: "
            )
        except (KeyboardInterrupt, EOFError) as exc:
            print("\nAborted.", file=sys.stderr)
            raise LoginError(f"Authentication aborted for {dns}.") from exc
        result = _bootstrap_from_credentials(
            catalog_url,
            username=prompted_username,
            password=prompted_password,
            name=name,
            expires_in_days=expires_in_days,
        )

    secret = str(result["secret"])
    expires_at = _parse_expires_at(result.get("expires_at"))
    if store:
        credentials.store(dns, secret, name=name, expires_at=expires_at)
    return MintedApiKey(secret=secret, name=name, expires_at=expires_at)


def print_stored_message(minted: MintedApiKey, dns: str) -> None:
    pretty_expiry = ""
    if minted.expires_at:
        expiry_dt = _dt.datetime.fromtimestamp(minted.expires_at, _dt.timezone.utc)
        pretty_expiry = f" (expires {expiry_dt.strftime('%Y-%m-%d')})"
    print(f"Stored API key '{minted.name}' for {dns}{pretty_expiry}.", file=sys.stderr)


def print_unstored_message(minted: MintedApiKey, dns: str) -> None:
    """Report a successful ephemeral mint without writing the secret to stderr."""
    pretty_expiry = ""
    if minted.expires_at:
        expiry_dt = _dt.datetime.fromtimestamp(minted.expires_at, _dt.timezone.utc)
        pretty_expiry = f" (expires {expiry_dt.strftime('%Y-%m-%d')})"
    print(
        f"Minted API key '{minted.name}' for {dns}{pretty_expiry}; not stored.",
        file=sys.stderr,
    )


def _resolve_password(args: argparse.Namespace) -> str | None:
    """Resolve a password using CLI, stdin, then environment precedence."""
    if args.username is None:
        if args.password is not None or args.password_stdin:
            raise LoginUsageError("--username is required with a password option.")
        return None

    if args.password is not None:
        return args.password

    if args.password_stdin:
        if sys.stdin.isatty():
            print("Reading password from stdin...", file=sys.stderr)
        try:
            password = sys.stdin.readline()
        except (KeyboardInterrupt, OSError) as exc:
            raise LoginUsageError("Could not read the password from stdin.") from exc
        password = password.removesuffix("\n").removesuffix("\r")
        if not password:
            raise LoginUsageError("No password was provided on stdin.")
        return password

    if "QUILTX_PASSWORD" not in os.environ:
        return None
    password = os.environ["QUILTX_PASSWORD"]
    if not password:
        raise LoginUsageError("QUILTX_PASSWORD is set but empty.")
    return password


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.catalog:
        print(
            "Error: --catalog <dns> is required for `quiltx catalog login`.",
            file=sys.stderr,
        )
        return 2

    try:
        dns = normalize_dns(args.catalog, insecure=args.insecure)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    catalog_url = build_catalog_url(dns, insecure=args.insecure)

    if args.api_key and (args.password is not None or args.password_stdin):
        print(
            "Error: --api-key cannot be combined with --password or "
            "--password-stdin.",
            file=sys.stderr,
        )
        return 2

    # Path 1: explicit --api-key (paste). Validate against the catalog before
    # optionally persisting so a bad paste never lands in credential storage.
    if args.api_key:
        if not args.api_key.startswith("qk_"):
            print("Error: API key must start with the 'qk_' prefix.", file=sys.stderr)
            return 1
        try:
            quilt_auth.validate_api_key(catalog_url, args.api_key)
        except quilt_auth.CatalogAuthError as exc:
            print(
                f"Error: pasted API key was rejected by {dns}: {exc}", file=sys.stderr
            )
            return 1
        if args.no_store:
            print(args.api_key)
            print(f"Validated API key for {dns}; not stored.", file=sys.stderr)
        else:
            credentials.store(dns, args.api_key, name=None, expires_at=None)
            print(f"Stored API key for {dns}.")
        return 0

    try:
        password = _resolve_password(args)
        minted = mint_api_key(
            catalog_url,
            dns,
            username=args.username,
            password=password,
            no_browser=args.no_browser,
            no_prompt=args.no_prompt,
            key_name=args.key_name,
            expires_in_days=args.expires_in_days,
            store=not args.no_store,
        )
    except LoginError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2 if isinstance(exc, LoginUsageError) else 1

    if args.no_store:
        print(minted.secret)
        print_unstored_message(minted, dns)
    else:
        print_stored_message(minted, dns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
