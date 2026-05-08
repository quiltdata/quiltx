"""Quilt catalog management commands."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module

SUBCOMMANDS = {
    "acl": "quiltx.tools.catalog.acl",
    "api-key": "quiltx.tools.catalog.api_key",
    "default": "quiltx.tools.catalog.default",
    "forget": "quiltx.tools.catalog.forget",
    "list": "quiltx.tools.catalog.list_",
    "login": "quiltx.tools.catalog.login",
    "stack": "quiltx.tools.catalog.stack",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog",
        description="Manage Quilt catalogs: default, credentials, ACLs, and CloudFormation discovery.",
    )

    subparsers = parser.add_subparsers(
        dest="subcommand",
        title="subcommands",
        metavar="SUBCOMMAND",
    )

    subparsers.add_parser(
        "acl",
        help="Reconcile Quilt bucket, role, policy, and SSO ACLs from YAML.",
        add_help=False,
    )
    subparsers.add_parser(
        "api-key",
        help="Mint, store, and print a new qk_... API key.",
        add_help=False,
    )
    subparsers.add_parser(
        "default",
        help="Read, set, or clear the default catalog.",
        add_help=False,
    )
    subparsers.add_parser(
        "forget",
        help="Delete keyring entry for a catalog.",
        add_help=False,
    )
    subparsers.add_parser(
        "list",
        help="List known catalogs (keyring entries).",
        add_help=False,
    )
    subparsers.add_parser(
        "login",
        help="Mint and store a qk_... API key from username/password.",
        add_help=False,
    )
    subparsers.add_parser(
        "stack",
        help="Discover and store CloudFormation stack information for the configured catalog.",
        add_help=False,
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()

    if not argv:
        parser.print_help()
        return 1

    args, remaining = parser.parse_known_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 1

    if args.subcommand not in SUBCOMMANDS:
        print(f"Error: Unknown subcommand '{args.subcommand}'", file=sys.stderr)
        return 1

    module = import_module(SUBCOMMANDS[args.subcommand])
    return module.main(remaining)


if __name__ == "__main__":
    raise SystemExit(main())
