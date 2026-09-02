"""Declarative ACL management for Quilt stacks."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from quiltx import acl as acl_lib
from quiltx import stack as stack_lib
from quiltx.cli_common import add_catalog_args, env_flag

MAX_CREATED_USERS_DEFAULT = 10
"""How many accounts one --create-and-email-users run may create unprompted.

The cap is small on purpose. A roster that grew past a handful of unknown
addresses is more often a config mistake — a whole community list pasted in, a
domain roster mistaken for a group selector — than an intended onboarding, and
the mail those addresses receive cannot be recalled.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog acl",
        description=(
            "Reconcile Quilt ACLs from flat YAML with top-level "
            "'policies:', 'roles:', and optional 'users:' and 'buckets:' blocks."
        ),
    )
    add_catalog_args(parser, auth_required=True)
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
        "--no-preflight",
        action="store_true",
        help=(
            "Register every new bucket via GraphQL only, skipping local AWS "
            "bucket-owner setup. Mark individual pre-prepared buckets with "
            "config.no_preflight under 'buckets:' instead."
        ),
    )
    parser.add_argument(
        "--create-and-email-users",
        action="store_true",
        help=(
            "Create an account for every sso.email address with no existing "
            "user. The registry mails each new account a welcome and "
            "password-reset link as part of creating it, and that send cannot "
            "be recalled, so this is never read from the config file."
        ),
    )
    parser.add_argument(
        "--max-created-users",
        type=int,
        # Not MAX_CREATED_USERS_DEFAULT: the validation below tests whether the
        # flag was supplied, and a default equal to the cap makes
        # `--max-created-users 10` alone indistinguishable from omitting it.
        default=None,
        metavar="N",
        help=(
            "Refuse --create-and-email-users when the rosters would create more "
            f"than N accounts in one run (default: {MAX_CREATED_USERS_DEFAULT})."
        ),
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit the complete current ACL state as JSON. "
            "Only valid when config_file is omitted."
        ),
    )
    output_group.add_argument(
        "--yaml",
        action="store_true",
        help=(
            "Emit current state as replayable ACL YAML. "
            "Only valid when config_file is omitted."
        ),
    )
    parser.add_argument(
        "--omit-default-users",
        action="store_true",
        help=(
            "Emit a concise declarative YAML export by omitting users assigned "
            "only to the default role. Requires --yaml and no config_file."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.omit_default_users and not args.yaml:
        parser.error("--omit-default-users requires --yaml")
    if (args.json or args.yaml) and args.config_file is not None:
        output_flag = "--json" if args.json else "--yaml"
        parser.error(f"{output_flag} is only valid when config_file is omitted")
    if args.create_and_email_users and args.config_file is None:
        parser.error("--create-and-email-users requires a config_file")
    if args.max_created_users is not None and not args.create_and_email_users:
        parser.error("--max-created-users requires --create-and-email-users")

    try:
        return _run(args)
    except Exception as exc:
        details = _format_exception_details(exc)
        if details:
            for detail in details:
                print(detail, file=sys.stderr)
        if args.verbose:
            print(f"Failure type: {type(exc).__name__}", file=sys.stderr)
        print(f"Error: {exc}", file=sys.stderr)
        return 1


@stack_lib.catalog_command
def _run(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    try:
        if not (args.json or args.yaml):
            header = stack_lib.current_stack_header(stack)
            if header:
                print(header)
        if args.config_file is None:
            current = acl_lib.fetch_current_state(stack)
            if args.json:
                print(
                    json.dumps(
                        acl_lib.current_state_as_dict(
                            current, catalog=stack.catalog_name
                        ),
                        indent=2,
                    )
                )
            elif args.yaml:
                exported, risk_warnings = (
                    acl_lib.current_state_as_acl_yaml_with_warnings(
                        current,
                        catalog=stack.catalog_name,
                        captured_on=date.today().isoformat(),
                        omit_default_users=args.omit_default_users,
                    )
                )
                print(exported, end="")
                # Repeat the embedded risk notes on stderr so they stay visible
                # when the YAML is redirected to a file. The analysis already
                # ran while rendering the YAML; do not parse+diff a second time.
                _print_export_downgrade_warnings(risk_warnings)
            else:
                acl_lib.print_current_state(current)
            return 0

        desired = acl_lib.parse_acl_config(args.config_file)
        current = acl_lib.fetch_current_state(stack)
        diff = acl_lib.compute_diff(desired, current)
        acl_lib.print_diff(diff, verbose=args.verbose, desired=desired, current=current)

        no_preflight = bool(args.no_preflight or env_flag("QUILTX_NO_PREFLIGHT"))

        # Creating roster accounts is not part of the diff, so a file that is
        # otherwise reconciled must not short-circuit it: that is exactly the
        # state a first apply leaves behind before anyone has been onboarded.
        if not diff.has_changes() and not args.create_and_email_users:
            return 0

        if args.dry_run:
            _print_no_preflight_notice(diff, no_preflight=no_preflight, dry_run=True)
            if args.create_and_email_users:
                _print_user_creation_dry_run(desired, current)
            return 0

        warnings: list[str] = []
        post_current = current
        if diff.has_changes():
            _print_no_preflight_notice(diff, no_preflight=no_preflight)
            if not args.yes and not _confirm_apply():
                print("Aborted.")
                return 1

            print("Applying...")
            warnings = acl_lib.apply_acl(
                stack,
                diff,
                current,
                verbose=args.verbose,
                assume_yes=args.yes,
                no_preflight=no_preflight,
            )

            post_current = acl_lib.fetch_current_state(stack)
            drift = acl_lib.detect_policy_drift(desired, post_current)
            if drift:
                reset_warnings, post_current = _handle_policy_drift(
                    stack,
                    drift,
                    desired,
                    post_current,
                    auto=args.yes,
                    verbose=args.verbose,
                    no_preflight=no_preflight,
                )
                warnings.extend(reset_warnings)

        if args.create_and_email_users:
            warnings.extend(
                _create_and_email_users(
                    stack,
                    desired,
                    post_current,
                    assume_yes=args.yes,
                    max_created=(
                        MAX_CREATED_USERS_DEFAULT
                        if args.max_created_users is None
                        else args.max_created_users
                    ),
                    verbose=args.verbose,
                )
            )

        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)

        # Ground truth, not a tally of what apply_acl reported: a bucket the
        # catalog still does not hold is a failure even when the add returned
        # cleanly, and it is the failure that makes every dependent policy fail.
        unregistered = [
            bucket
            for bucket in diff.buckets_to_add
            if bucket not in post_current.buckets
        ]
        if unregistered:
            print(
                f"!! {len(unregistered)} bucket(s) are still not registered: "
                + ", ".join(unregistered),
                file=sys.stderr,
            )
        if warnings or unregistered:
            summary = f"Done with {len(warnings)} warning(s)"
            if unregistered:
                summary += f" and {len(unregistered)} unregistered bucket(s)"
            print(f"{summary}.", file=sys.stderr)
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


def _print_export_downgrade_warnings(warnings: list[str]) -> None:
    """Announce export privilege-loss risks on stderr."""
    if not warnings:
        return
    print(
        f"!! WARNING: ACL export found {len(warnings)} downgrade-risk item(s):",
        file=sys.stderr,
    )
    for warning in warnings:
        print(f"  - {warning}", file=sys.stderr)
    print(
        "Applying this file as-is may downgrade existing users. "
        "See the '# not captured:' notes in the generated YAML.",
        file=sys.stderr,
    )


def _confirm_apply() -> bool:
    return input("Apply ACL changes? [y/N]: ").strip().lower() in {"y", "yes"}


def _confirm_create_and_email(count: int) -> bool:
    return input(f"Create and email {count} account(s)? [y/N]: ").strip().lower() in {
        "y",
        "yes",
    }


def _unmakeable_accounts(plan: acl_lib.UserCreationPlan) -> str:
    """Keep a plan of nothing-but-warnings from reading as a fully-onboarded one.

    Only ``warnings`` count. A ``notices`` entry is an address that needs nothing
    done and is therefore already in ``existing``; counting it here would both
    report one address twice and label a held address uncreatable.
    """
    if not plan.warnings:
        return ""
    return f" and {len(plan.warnings)} cannot be created"


def _print_user_creation_notices(plan: acl_lib.UserCreationPlan) -> None:
    """Report the addresses that need nothing done but are worth knowing about.

    Printed here rather than returned, because only ``warnings`` travel back to
    ``_run`` and everything that reaches it decides the exit code. Same ``!``
    prefix as a warning: the operator reads one list of remarks about the roster,
    and the split is about the exit code, not about how loud each entry is.
    """
    for notice in plan.notices:
        print(f"! {notice}")


def _print_user_creation_dry_run(
    desired: acl_lib.AclConfig, current: acl_lib.CurrentState
) -> None:
    """Name the accounts a real run would create, and therefore mail."""
    plan = acl_lib.plan_user_creations(desired, current)
    print()
    if plan.creations:
        acl_lib.print_user_creations(plan, dry_run=True)
    else:
        print(
            f"No accounts would be created: {len(plan.existing)} roster "
            f"address(es) already have one{_unmakeable_accounts(plan)}."
        )
    _print_user_creation_notices(plan)
    # A dry run returns nothing, so its warnings are printed here too or lost.
    for warning in plan.warnings:
        print(f"! {warning}")


def _create_and_email_users(
    stack: stack_lib.Catalog,
    desired: acl_lib.AclConfig,
    current: acl_lib.CurrentState,
    *,
    assume_yes: bool,
    max_created: int,
    verbose: bool,
) -> list[str]:
    """Create the accounts the sso.email rosters name and the server lacks.

    Called after role reconciliation and after any drift reset, because the
    registry rejects a creation naming a role it does not hold and the reset pass
    is what puts the last of those roles in place. *current* is therefore the
    server state as of that point, which is also what makes the "already has an
    account" check accurate on a second pass.

    The addresses are printed before the prompt because the welcome mail is sent
    by the creation itself: after this returns there is nothing left to confirm.
    """
    plan = acl_lib.plan_user_creations(desired, current)
    warnings = list(plan.warnings)
    _print_user_creation_notices(plan)
    if not plan.creations:
        print(
            f"No accounts to create: {len(plan.existing)} roster address(es) "
            f"already have one{_unmakeable_accounts(plan)}."
        )
        return warnings

    acl_lib.print_user_creations(plan)
    if len(plan.creations) > max_created:
        refusal = (
            f"Refusing to create and email {len(plan.creations)} account(s): "
            f"more than --max-created-users ({max_created}). Re-run with "
            f"--max-created-users {len(plan.creations)} once the addresses "
            "above have been reviewed."
        )
        print(f"!! REFUSED: {refusal}", file=sys.stderr)
        warnings.append(refusal)
        return warnings
    if not assume_yes and not _confirm_create_and_email(len(plan.creations)):
        warnings.append(
            f"{len(plan.creations)} roster account(s) were not created "
            "(user declined)."
        )
        return warnings

    print("Creating and emailing users...")
    warnings.extend(acl_lib.create_roster_users(stack, plan.creations, verbose=verbose))
    return warnings


def _print_no_preflight_notice(
    diff: acl_lib.AclDiff, *, no_preflight: bool, dry_run: bool = False
) -> None:
    """Name the new buckets registered via GraphQL only, and why.

    The mode is per bucket, so a global claim would be a guess: an apply can mix
    pre-prepared buckets declared in the file with buckets this identity does
    prepare itself. Each bucket is listed with the source that put it in
    GraphQL-only mode so the run can be checked against the file.

    Printed on a real apply as well as a dry run. Whether a bucket's AWS setup
    was verified locally or taken on trust is the kind of fact someone reads back
    off a ``--yes`` CI log months later, and only the file it ran against could
    otherwise answer it.
    """
    sources = {
        bucket: (
            f"buckets.{bucket}.{acl_lib.CONFIG_NO_PREFLIGHT_KEY}"
            if bucket in diff.no_preflight_buckets
            else "--no-preflight"
        )
        for bucket in diff.buckets_to_add
        if no_preflight or bucket in diff.no_preflight_buckets
    }
    if not sources:
        return
    print()
    verb = "would be" if dry_run else "will be"
    print(
        f"{len(sources)} new bucket(s) {verb} registered via GraphQL only, "
        "skipping local AWS bucket-owner setup:"
    )
    for bucket, source in sources.items():
        print(f"  - {bucket} ({source})")
    print("Skipped local AWS steps per bucket:")
    for item in (
        "GetBucketLocation",
        "GetBucketPolicy / PutBucketPolicy",
        "SNS topic creation and policy configuration",
        "bucket-notification configuration",
        "post-add verification",
    ):
        print(f"  - {item}")


def _handle_policy_drift(
    stack: stack_lib.Catalog,
    drift: list[acl_lib.PolicyDrift],
    desired: acl_lib.AclConfig,
    current: acl_lib.CurrentState,
    *,
    auto: bool,
    verbose: bool,
    no_preflight: bool = False,
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
                f"    reset would delete+recreate roles: {', '.join(affected_roles)}",
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

    affected_users = acl_lib.users_assigned_to_roles(stack, all_affected_roles)
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
            stack,
            title,
            current,
            verbose=verbose,
            already_deleted_roles=deleted_roles,
        )
        warnings.extend(reset_warnings)
        user_snapshots.extend(snap)

    post_reset = acl_lib.fetch_current_state(stack)
    new_diff = acl_lib.compute_diff(desired, post_reset)
    if new_diff.has_changes():
        print("Reapplying after reset...")
        warnings.extend(
            acl_lib.apply_acl(
                stack,
                new_diff,
                post_reset,
                verbose=verbose,
                assume_yes=auto,
                no_preflight=no_preflight,
            )
        )
        post_reset = acl_lib.fetch_current_state(stack)

    if user_snapshots:
        print("Restoring user role bindings...")
        warnings.extend(
            acl_lib.restore_user_role_bindings(stack, user_snapshots, verbose=verbose)
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
