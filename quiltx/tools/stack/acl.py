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
        desired = acl_lib.with_default_role(
            desired,
            _resolve_default_role_name(
                desired,
                prompt_for_choice=not args.yes,
            ),
        )
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
        if args.verbose:
            print(f"Failure type: {type(exc).__name__}", file=sys.stderr)
            for detail in _format_exception_details(exc):
                print(detail, file=sys.stderr)
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _confirm_apply() -> bool:
    return input("Apply ACL changes? [y/N]: ").strip().lower() in {"y", "yes"}


def _resolve_default_role_name(
    config: acl_lib.AclConfig, *, prompt_for_choice: bool
) -> str | None:
    if config.default_role_name is not None:
        return config.default_role_name

    role_names = list(config.roles)
    if not role_names:
        return None

    if not prompt_for_choice:
        return role_names[0]

    if not sys.stdin.isatty():
        return role_names[0]

    print("Select the default role:")
    for index, role_name in enumerate(role_names, start=1):
        print(f"  {index}. {role_name}")

    try:
        response = input(f"Default role [1-{len(role_names)}] (default 1): ").strip()
    except EOFError:
        return role_names[0]
    if response == "":
        return role_names[0]

    try:
        selected = int(response)
    except ValueError as exc:
        raise ValueError(f"Invalid default role selection: {response!r}") from exc

    if not 1 <= selected <= len(role_names):
        raise ValueError(f"Default role selection out of range: {selected}")

    return role_names[selected - 1]


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
