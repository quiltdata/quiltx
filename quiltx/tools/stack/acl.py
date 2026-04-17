"""Declarative ACL management for Quilt stacks."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace

from quiltx import acl as acl_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx stack acl",
        description=(
            "Reconcile Quilt ACLs from flat YAML with top-level "
            "'policies:' and 'roles:' blocks."
        ),
    )
    parser.add_argument(
        "config_file",
        nargs="?",
        default=None,
        help=(
            "Path to the ACL YAML file. Use the flat policies/roles format "
            "from spec/060-stack-acl/simpler-stack-acl.yml. If omitted, "
            "shows current server state."
        ),
    )
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
    parser.add_argument(
        "--store-last-login-context",
        action="store_true",
        default=False,
        help="Enable store_last_login_context in SSO config for debugging.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.config_file is None:
            current = acl_lib.fetch_current_state()
            acl_lib.print_current_state(current)
            return 0

        desired = acl_lib.parse_acl_config(args.config_file)
        if args.store_last_login_context:
            desired = replace(desired, store_last_login_context=True)
        current = acl_lib.fetch_current_state()
        diff = acl_lib.compute_diff(desired, current)
        acl_lib.print_diff(diff, verbose=args.verbose, desired=desired, current=current)

        if not diff.has_changes():
            return 0

        if args.dry_run:
            return 0

        if not args.yes and not _confirm_apply():
            print("Aborted.")
            return 1

        print("Applying...")
        warnings = acl_lib.apply_acl(diff, current, verbose=args.verbose)
        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)
        print("Done.")
        return 0
    except Exception as exc:
        details = _format_exception_details(exc)
        if details:
            for detail in details:
                print(detail, file=sys.stderr)
        if args.verbose:
            print(f"Failure type: {type(exc).__name__}", file=sys.stderr)
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _confirm_apply() -> bool:
    return input("Apply ACL changes? [y/N]: ").strip().lower() in {"y", "yes"}


def _format_exception_details(exc: Exception) -> list[str]:
    details: list[str] = []
    errors = getattr(exc, "errors", None)
    if not isinstance(errors, list):
        return details

    for index, error in enumerate(errors, start=1):
        message = getattr(error, "message", None)
        if message:
            details.append(f"GraphQL error {index}: {message}")
        path = getattr(error, "path", None)
        if path:
            details.append(f"GraphQL path {index}: {path}")
        locations = getattr(error, "locations", None)
        if locations:
            details.append(f"GraphQL locations {index}: {locations}")
    return details


if __name__ == "__main__":
    raise SystemExit(main())
