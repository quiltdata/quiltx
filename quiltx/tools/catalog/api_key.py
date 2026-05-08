"""Mint and display a Quilt catalog API key."""

from __future__ import annotations

import argparse
import sys

from quiltx import credentials
from quiltx.cli_common import add_catalog_args
from quiltx.identity import build_catalog_url, normalize_dns
from quiltx.tools.catalog import login as login_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog api-key",
        description=(
            "Print the stored qk_... API key for a catalog. Use --new to "
            "mint, store, and print a replacement key."
        ),
    )
    add_catalog_args(parser, auth_required=False)
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=False,
        help=(
            "Allow http:// transport to localhost for testing local catalog "
            "builds. Refused for any non-localhost target. Never persisted."
        ),
    )
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
    parser.add_argument(
        "--new",
        action="store_true",
        help="Mint and store a new API key instead of printing the stored key.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.catalog:
        print(
            "Error: --catalog <dns> is required for `quiltx catalog api-key`.",
            file=sys.stderr,
        )
        return 2

    try:
        dns = normalize_dns(args.catalog, insecure=args.insecure)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not args.new:
        stored = credentials.get(dns)
        if stored is not None:
            print(stored["api_key"])
            return 0
        if args.no_prompt:
            print(f"Error: no stored API key for {dns}.", file=sys.stderr)
            return 1

    catalog_url = build_catalog_url(dns, insecure=args.insecure)

    try:
        minted = login_cmd.mint_api_key(
            catalog_url,
            dns,
            username=args.username,
            password=args.password,
            no_browser=args.no_browser,
            no_prompt=args.no_prompt,
            key_name=args.key_name,
            expires_in_days=args.expires_in_days,
        )
    except login_cmd.LoginError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2 if login_cmd.is_usage_error(exc) else 1

    login_cmd.print_stored_message(minted, dns)
    print(minted.secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
