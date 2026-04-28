"""Declarative ACL management for Quilt stacks."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace

from quiltx import acl as acl_lib
from quiltx import stack as stack_lib


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
            "from stack-acl.example.yaml. If omitted, "
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
        ctx = stack_lib.resolve_stack_context()
        header = stack_lib.current_stack_header(ctx)
        if header:
            print(header)
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
        warnings = acl_lib.apply_acl(
            diff, current, verbose=args.verbose, assume_yes=args.yes
        )

        post_current = acl_lib.fetch_current_state()
        drift = acl_lib.detect_policy_drift(desired, post_current)
        if drift:
            reset_warnings, post_current = _handle_policy_drift(
                drift, desired, post_current, auto=args.yes, verbose=args.verbose
            )
            warnings.extend(reset_warnings)

        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)
        if warnings:
            print(f"Done with {len(warnings)} warning(s).", file=sys.stderr)
            return 1
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


def _handle_policy_drift(
    drift: list[acl_lib.PolicyDrift],
    desired: acl_lib.AclConfig,
    current: acl_lib.CurrentState,
    *,
    auto: bool,
    verbose: bool,
) -> tuple[list[str], acl_lib.CurrentState]:
    """Prompt for (or auto-apply) policy resets when server state has drifted.

    Always-on detection: any managed policy whose server state differs from
    the desired config is a candidate for delete+recreate via the create
    codepath, which bypasses bugs on the update codepath.
    """
    warnings: list[str] = []
    print(
        f"Detected {len(drift)} managed polic"
        f"{'y' if len(drift) == 1 else 'ies'} that did not reach the "
        f"desired state after apply.",
        file=sys.stderr,
    )
    to_reset: list[str] = []
    all_affected_roles: set[str] = set()
    for item in drift:
        affected_roles = acl_lib.managed_roles_using_policy(item.title, current)
        all_affected_roles.update(affected_roles)
        print(f"  policy {item.title}:", file=sys.stderr)
        if item.missing:
            print(f"    missing on server: {', '.join(item.missing)}", file=sys.stderr)
        if item.extra:
            print(f"    extra on server:   {', '.join(item.extra)}", file=sys.stderr)
        if affected_roles:
            print(
                f"    reset would delete+recreate roles: "
                f"{', '.join(affected_roles)}",
                file=sys.stderr,
            )
        if auto:
            print("    auto-reset: yes (--yes)", file=sys.stderr)
            to_reset.append(item.title)
        else:
            answer = input(f"  Reset policy {item.title}? [y/N]: ").strip().lower()
            if answer in {"y", "yes"}:
                to_reset.append(item.title)
            else:
                warnings.append(
                    f"Policy '{item.title}' left in drifted state (user declined reset)"
                )

    if not to_reset:
        return warnings, current

    affected_users = acl_lib.users_assigned_to_roles(all_affected_roles)
    if affected_users:
        print(
            "WARNING: the following users will be temporarily reassigned "
            "to the default role while their roles are recreated:",
            file=sys.stderr,
        )
        for binding in affected_users:
            primary = binding.primary or "(none)"
            extras = ", ".join(binding.extras) if binding.extras else "(none)"
            print(
                f"  - {binding.user_name}: primary={primary} extras={extras}",
                file=sys.stderr,
            )
        print(
            "  If you are one of these users, your active session may need "
            "to re-authenticate after the reset completes.",
            file=sys.stderr,
        )

    print("Resetting drifted policies...")
    user_snapshots: list[acl_lib.UserRoleBinding] = []
    deleted_roles: set[str] = set()
    for title in to_reset:
        reset_warnings, snap = acl_lib.reset_policy(
            title,
            current,
            verbose=verbose,
            already_deleted_roles=deleted_roles,
        )
        warnings.extend(reset_warnings)
        user_snapshots.extend(snap)

    post_reset = acl_lib.fetch_current_state()
    new_diff = acl_lib.compute_diff(desired, post_reset)
    if new_diff.has_changes():
        print("Reapplying after reset...")
        warnings.extend(
            acl_lib.apply_acl(new_diff, post_reset, verbose=verbose, assume_yes=auto)
        )
        post_reset = acl_lib.fetch_current_state()

    if user_snapshots:
        print("Restoring user role bindings...")
        warnings.extend(
            acl_lib.restore_user_role_bindings(user_snapshots, verbose=verbose)
        )

    residual = acl_lib.detect_policy_drift(desired, post_reset)
    for item in residual:
        warnings.append(
            f"Policy '{item.title}' still drifted after reset: "
            f"missing={item.missing or '[]'} extra={item.extra or '[]'}"
        )
    return warnings, post_reset


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
