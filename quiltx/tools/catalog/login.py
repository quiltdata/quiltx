"""quiltx catalog login: mint a qk_... API key and store it.

Bootstrap flow: username/password → catalog refresh_token → access_token →
GraphQL ``apiKeyCreate`` → qk_... secret → keyring. SSO-only catalogs
reject U/P at /api/login; the catalog's own error message is surfaced
verbatim and the command exits non-zero so the user can paste a
manually-issued key via --api-key instead.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import socket
import sys

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog login",
        description=(
            "Mint a qk_... API key from username/password and store it in "
            "the system keyring. Use --api-key to skip the bootstrap and "
            "store an existing key directly."
        ),
    )
    add_catalog_args(parser, auth_required=True)
    parser.add_argument(
        "--username",
        help="Catalog admin username for U/P -> API-key bootstrap.",
    )
    parser.add_argument(
        "--password",
        help=(
            "Catalog admin password. If --username is given without --password "
            "in interactive mode, you will be prompted."
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
        print(f"Error: {message}", file=sys.stderr)
        if "sso" in message.lower() or "401" in message:
            print(
                "If this catalog uses SSO, mint a key from the catalog UI and "
                "pass it via --api-key.",
                file=sys.stderr,
            )
        raise SystemExit(1)


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

    # Path 1: explicit --api-key (paste). No network round-trip; the prefix
    # check is the only validation. The first real command that uses the
    # key will fail loudly if it is rejected by the catalog.
    if args.api_key:
        if not args.api_key.startswith("qk_"):
            print("Error: API key must start with the 'qk_' prefix.", file=sys.stderr)
            return 1
        credentials.store(dns, args.api_key, name=None, expires_at=None)
        print(f"Stored API key for {dns}.")
        return 0

    # Path 2/3: U/P bootstrap, either from flags or from interactive prompt.
    username = args.username
    password = args.password
    interactive = not args.no_prompt and sys.stdin.isatty()

    if username is None:
        if not interactive:
            print(
                "Error: --username is required (or pass --api-key, or run "
                "interactively).",
                file=sys.stderr,
            )
            return 2
        try:
            username = input(f"Username for {dns}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            return 1
        if not username:
            print("Error: username is required.", file=sys.stderr)
            return 1

    if password is None:
        if not interactive:
            print(
                "Error: --password is required when --username is set " "headlessly.",
                file=sys.stderr,
            )
            return 2
        try:
            password = getpass.getpass(f"Password for {username}@{dns}: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            return 1

    name = args.key_name or _default_key_name()
    result = _bootstrap_from_credentials(
        catalog_url,
        username=username,
        password=password,
        name=name,
        expires_in_days=args.expires_in_days,
    )

    secret = str(result["secret"])
    expires_at = _parse_expires_at(result.get("expires_at"))
    credentials.store(dns, secret, name=name, expires_at=expires_at)

    pretty_expiry = ""
    if expires_at:
        expiry_dt = _dt.datetime.fromtimestamp(expires_at, _dt.timezone.utc)
        pretty_expiry = f" (expires {expiry_dt.strftime('%Y-%m-%d')})"
    print(f"Stored API key '{name}' for {dns}{pretty_expiry}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
