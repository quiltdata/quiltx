"""Quilt stack management commands."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module

SUBCOMMANDS = {
    "acl": "quiltx.tools.stack.acl",
    "catalog": "quiltx.tools.stack.catalog",
    "cfn": "quiltx.tools.stack.cfn",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx stack",
        description="Manage Quilt stack: catalog connection, CloudFormation discovery, and access control.",
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
        "catalog",
        help="Show or set the Quilt catalog configured by quilt3.",
        add_help=False,
    )
    subparsers.add_parser(
        "cfn",
        help="Discover and store information about the CloudFormation stack for the configured catalog.",
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
