"""Declarative ACL management for Quilt stacks."""

from __future__ import annotations

import argparse
import sys

from quiltx import acl as acl_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx stack acl",
        description="Reconcile Quilt bucket, role, policy, and SSO ACLs from YAML.",
    )
    parser.add_argument("config_file", help="Path to the ACL YAML file.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Apply changes without prompting for confirmation.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned changes without applying them.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed information about each change.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        desired = acl_lib.parse_acl_config(args.config_file)
        current = acl_lib.fetch_current_state()
        diff = acl_lib.compute_diff(desired, current)
        acl_lib.print_diff(diff, verbose=args.verbose)

        if not diff.has_changes():
            return 0

        if args.dry_run:
            return 0

        if not args.yes and not _confirm_apply():
            print("Aborted.")
            return 1

        print("Applying...")
        warnings = acl_lib.apply_acl(diff, current)
        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)
        print("Done.")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _confirm_apply() -> bool:
    return input("Apply ACL changes? [y/N]: ").strip().lower() in {"y", "yes"}


if __name__ == "__main__":
    raise SystemExit(main())
