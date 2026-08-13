"""Register S3 buckets with the configured Quilt catalog."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from typing import Any, Mapping

import boto3
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from quiltx import bucket as bucket_lib
from quiltx import stack as stack_lib
from quiltx.cli_common import add_catalog_args, env_flag as _env_flag


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx bucket",
        description="Register S3 buckets with the configured Quilt catalog.",
    )
    subparsers = parser.add_subparsers(
        dest="action",
        title="actions",
        metavar="ACTION",
    )

    add_parser = subparsers.add_parser(
        "add",
        prog="quiltx bucket add",
        help="Register a bucket and configure bucket/SNS notifications.",
    )
    add_catalog_args(add_parser, auth_required=True)
    add_parser.add_argument("bucket_name", help="S3 bucket name to register.")
    add_parser.add_argument(
        "--title",
        help="Catalog display title for the bucket (defaults to bucket name).",
    )
    add_parser.add_argument(
        "--profile",
        help="AWS profile for the data account that owns the bucket.",
    )
    add_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned bucket/SNS changes without mutating AWS or Quilt.",
    )
    add_parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Apply changes without prompting for confirmation. "
            "Not needed with --no-preflight, which never prompts."
        ),
    )
    add_parser.add_argument(
        "--no-test",
        action="store_true",
        help="Skip the post-add registration/read verification.",
    )
    add_parser.add_argument(
        "--no-preflight",
        action="store_true",
        help=(
            "Skip local AWS preflight/setup and submit bucketAdd directly, "
            "letting the catalog stack probe the bucket. Never prompts for "
            "confirmation (--yes is not required)."
        ),
    )
    add_parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "If the bucket is already registered, remove it from the catalog "
            "first and then re-add it (so Quilt re-subscribes its SQS queues "
            "to the SNS topic). Reapplies bucket policy and SNS configuration."
        ),
    )

    remove_parser = subparsers.add_parser(
        "remove",
        prog="quiltx bucket remove",
        help="Unregister a bucket from the Quilt catalog.",
    )
    add_catalog_args(remove_parser, auth_required=True)
    remove_parser.add_argument("bucket_name", help="S3 bucket name to unregister.")
    remove_parser.add_argument(
        "--yes",
        action="store_true",
        help="Remove without prompting for confirmation.",
    )
    add_parser.add_argument(
        "--principal",
        metavar="ARN",
        action="append",
        nargs="?",
        const="",
        help=(
            "IAM role ARN(s) granted cross-account access in the bucket policy. "
            "Repeatable or comma-separated. Defaults to the control account root. "
            "Use the bare flag (no value) to print guidance on choosing principals."
        ),
    )

    prepare_parser = subparsers.add_parser(
        "prepare",
        prog="quiltx bucket prepare",
        help="Configure bucket access and notifications using AWS credentials only.",
    )
    prepare_parser.add_argument("bucket_name", help="S3 bucket name to prepare.")
    prepare_parser.add_argument(
        "--profile",
        help="AWS profile for the data account that owns the bucket.",
    )
    prepare_parser.add_argument(
        "--control-account-id",
        help=(
            "Quilt control AWS account ID. Required unless --principal or "
            "--catalog is supplied; defaults access to that account root."
        ),
    )
    prepare_parser.add_argument(
        "--catalog",
        help=(
            "Catalog DNS name used to derive the control account ID when "
            "--control-account-id and --principal are omitted: reads cached "
            "stack metadata, else logs in as a regular catalog user (no admin "
            "required) and asks STS which account minted the credentials."
        ),
    )
    prepare_parser.add_argument(
        "--principal",
        metavar="ARN",
        action="append",
        nargs="?",
        const="",
        help=(
            "Explicit Quilt IAM role ARN granted bucket and SNS access. "
            "Repeatable or comma-separated."
        ),
    )
    output_group = prepare_parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the exact final AWS policy and notification documents.",
    )
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Print only the minimal non-secret operator handoff as JSON.",
    )
    prepare_parser.add_argument(
        "--yes",
        action="store_true",
        help="Apply AWS changes without prompting for confirmation.",
    )

    list_parser = subparsers.add_parser(
        "list",
        prog="quiltx bucket list",
        help="List buckets registered in the catalog.",
    )
    add_catalog_args(list_parser, auth_required=True)

    profile_parser = subparsers.add_parser(
        "profile",
        prog="quiltx bucket profile",
        help=(
            "List available AWS profiles, or find which profile can access a bucket."
        ),
    )
    profile_parser.add_argument(
        "bucket_name",
        nargs="?",
        help="If given, find the first AWS profile that can access this bucket.",
    )

    test_parser = subparsers.add_parser(
        "test",
        prog="quiltx bucket test",
        help="Verify the control account can read the bucket (tests cross-account policy).",
    )
    add_catalog_args(test_parser, auth_required=True)
    test_parser.add_argument("bucket_name", help="S3 bucket name to test.")

    reindex_parser = subparsers.add_parser(
        "reindex",
        prog="quiltx bucket reindex",
        help=(
            "Re-scan an S3 prefix on a registered bucket so that newly arrived "
            "objects (added without S3 notifications) get into the search index. "
            "Calls POST /api/admin/reindex/<bucket> with the prefix; the bucket's "
            "existing ES indices are NOT wiped."
        ),
    )
    add_catalog_args(reindex_parser, auth_required=True)
    reindex_parser.add_argument(
        "s3_uri",
        help=(
            "S3 URI to reindex, e.g. 's3://my-bucket/some/prefix/'. "
            "Use 's3://my-bucket/' to reindex the whole bucket (this wipes "
            "and recreates the bucket's ES indices)."
        ),
    )
    reindex_parser.add_argument(
        "--profile",
        help="AWS profile to use for the dry-run S3 listing.",
    )
    reindex_parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "List a sample of keys under the prefix and print the count; "
            "do NOT POST to the registry."
        ),
    )
    reindex_parser.add_argument(
        "--sample",
        type=int,
        default=10,
        help="Number of sample keys to print in --dry-run mode (default: 10).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.action == "add":
            return _cmd_add(args)
        if args.action == "prepare":
            return _cmd_prepare(args)
        if args.action == "remove":
            return _cmd_remove(args)
        if args.action == "list":
            return _cmd_list(args)
        if args.action == "profile":
            return _cmd_profile(args)
        if args.action == "test":
            return _cmd_test(args)
        if args.action == "reindex":
            return _cmd_reindex(args)
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        _print_exception(exc)
        return 1

    parser.print_help()
    return 1


def _print_exception(exc: BaseException) -> None:
    """Render a caught exception with type and (when verbose) traceback."""
    print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
    if os.environ.get("QUILTX_VERBOSE"):
        traceback.print_exception(exc, file=sys.stderr)


def parse_s3_uri(uri: str) -> tuple[str, str]:
    """Parse an ``s3://bucket/prefix`` URI into ``(bucket, prefix)``.

    Raises ``ValueError`` for malformed input.
    """
    if not uri.startswith("s3://"):
        raise ValueError(
            f"Expected an s3:// URI, got {uri!r}. "
            "Example: s3://my-bucket/some/prefix/"
        )
    rest = uri[len("s3://") :]
    if not rest:
        raise ValueError("S3 URI is missing a bucket name.")
    if "/" in rest:
        bucket, prefix = rest.split("/", 1)
    else:
        bucket, prefix = rest, ""
    if not bucket:
        raise ValueError(f"S3 URI has an empty bucket name: {uri!r}")
    return bucket, prefix


def _cmd_reindex(args: argparse.Namespace) -> int:
    try:
        bucket_name, prefix = parse_s3_uri(args.s3_uri)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        return _reindex_dry_run(bucket_name, prefix, args)
    return _reindex_post(args, bucket_name, prefix)


def _reindex_dry_run(bucket_name: str, prefix: str, args: argparse.Namespace) -> int:
    """List a sample of keys under *prefix* without POSTing to the registry."""
    session, s3_client, _bucket_region, _resolved_profile = (
        bucket_lib.resolve_bucket_session(
            bucket_name,
            args.profile,
            assume_yes=True,
        )
    )
    if session is None:
        return 1

    paginator = s3_client.get_paginator("list_object_versions")
    sample: list[str] = []
    seen = 0
    sample_limit = max(0, args.sample)
    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        for entry in page.get("Versions") or []:
            seen += 1
            if len(sample) < sample_limit:
                sample.append(str(entry.get("Key", "")))
        for entry in page.get("DeleteMarkers") or []:
            seen += 1
            if len(sample) < sample_limit:
                sample.append(str(entry.get("Key", "")) + "  (delete-marker)")

    print(f"Dry-run: would reindex prefix {prefix!r} on bucket {bucket_name!r}.")
    print(f"  Object versions found: {seen}")
    if sample:
        shown = min(sample_limit, len(sample))
        print(f"  Sample keys ({shown}):")
        for key in sample[:shown]:
            print(f"    {key}")
    elif seen == 0:
        print("  (no object versions matched this prefix)")
    else:
        print("  (--sample 0: key display suppressed)")
    return 0


@stack_lib.catalog_command
def _reindex_post(
    stack: stack_lib.Catalog,
    args: argparse.Namespace,
    bucket_name: str,
    prefix: str,
) -> int:
    from quilt3 import session as quilt3_session

    registry_url = quilt3_session.get_registry_url()
    if not registry_url:
        print(
            "Error: no Quilt registry is configured. Run `quilt3 config` first.",
            file=sys.stderr,
        )
        return 1

    url = f"{registry_url.rstrip('/')}/api/admin/reindex/{bucket_name}"
    payload: dict[str, Any] = {}
    if prefix:
        payload["prefix"] = prefix

    http = quilt3_session.get_session()
    response = http.post(url, json=payload)
    if response.status_code == 409:
        print(
            f"Error: a reindex is already in progress for "
            f"s3://{bucket_name}/{prefix} (HTTP 409).",
            file=sys.stderr,
        )
        return 1
    if response.status_code == 404:
        print(
            f"Error: bucket {bucket_name!r} is not registered in this catalog.",
            file=sys.stderr,
        )
        return 1
    if not response.ok:
        print(
            f"Error: registry returned HTTP {response.status_code}: {response.text}",
            file=sys.stderr,
        )
        return 1

    target = f"s3://{bucket_name}/{prefix}" if prefix else f"s3://{bucket_name}"
    print(f"Enqueued reindex for {target}.")
    if not prefix:
        print("(no prefix supplied — full bucket reindex)")
    return 0


def _ensure_stack_payload(stack: stack_lib.Catalog) -> Mapping[str, Any]:
    """Load cached stack payload, or derive a lightweight one from the Quilt session."""
    return stack_lib.ensure_stack_payload(
        stack,
        allow_lightweight=True,
        announce=print,
        warn=lambda message: print(message, file=sys.stderr),
    )


def _lightweight_stack_payload(
    stack: stack_lib.Catalog,
    catalog_name: str,
    catalog_url: str,
    region: str,
    catalog_config: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Build an in-memory stack payload from the ambient AWS chain (no CFN calls).

    Per spec [06 §3.3]: do not import quilt3; use boto3.Session(region_name=...)
    against the ambient AWS credential chain. If that chain has no credentials,
    boto3 raises NoCredentialsError, which we surface with a hint to configure AWS.
    """
    if catalog_name != stack.catalog_name or catalog_url != stack.catalog_url:
        stack = stack_lib.Catalog(
            catalog_name=catalog_name,
            catalog_url=catalog_url,
            source=stack.source,
            auth_required=stack.auth_required,
        )
    return stack_lib.lightweight_stack_payload(
        stack,
        catalog_config=catalog_config,
        region=region,
    )


def _print_plan_documents(
    console: Console, plan: bucket_lib.BucketPreparationPlan
) -> None:
    print("\nFinal bucket policy:")
    _print_json(console, plan.bucket_policy)
    print("\nFinal SNS topic policy:")
    _print_json(console, plan.sns_policy)
    print("\nFinal bucket notification configuration:")
    _print_json(console, plan.notification_configuration)


def _print_bucket_preparation_plan(plan: bucket_lib.BucketPreparationPlan) -> None:
    console = Console(width=120)
    print("Bucket prepare dry-run")
    print(f"Bucket: s3://{plan.bucket}")
    print(f"Region: {plan.region}")
    print(f"Owning account: {plan.owning_account}")
    print(f"Effective principals: {', '.join(plan.principals)}")
    print(f"SNS topic: {plan.sns_topic_arn}")
    _print_plan_documents(console, plan)


def _control_account_id_from_catalog(catalog_arg: str) -> str:
    """Derive the Quilt control account ID for a catalog without admin access.

    Cached stack metadata wins (no authentication at all); otherwise log in as
    a regular catalog user and ask STS which account minted the catalog
    credentials. Keeps ``bucket prepare`` outside ``catalog_command``: no
    catalog configuration is loaded and no Quilt admin API is called.
    """
    from quiltx import quilt3_facade

    catalog = stack_lib.resolve_catalog_context(catalog_arg)
    payload = stack_lib.load_stack_payload(catalog.catalog_name)
    account_id = str((payload or {}).get("account_id") or "")
    if account_id:
        print(
            f"Control account {account_id} from cached stack metadata for "
            f"{catalog.catalog_name}.",
            file=sys.stderr,
        )
        return account_id
    catalog.ensure_auth()
    account_id = quilt3_facade.catalog_sts_account_id()
    print(
        f"Control account {account_id} from {catalog.catalog_name} catalog "
        "credentials.",
        file=sys.stderr,
    )
    return account_id


def _confirm_bucket_preparation(plan: bucket_lib.BucketPreparationPlan) -> bool:
    print(f"Prepare s3://{plan.bucket} in {plan.region} for Quilt access.")
    print(f"SNS topic: {plan.sns_topic_arn}")
    response = input("Apply these AWS changes? [y/N]: ").strip().lower()
    return response in {"y", "yes"}


def _cmd_prepare(args: argparse.Namespace) -> int:
    principals, show_guidance = _resolve_principals_arg(args.principal)
    if show_guidance:
        _print_principal_guidance()
        return 0
    for principal in principals:
        if not principal.startswith("arn:aws:iam::") or ":role/" not in principal:
            print(
                f"Error: --principal must be an IAM role ARN, got {principal!r}",
                file=sys.stderr,
            )
            return 1
    if args.control_account_id and (
        len(args.control_account_id) != 12 or not args.control_account_id.isdigit()
    ):
        print(
            "Error: --control-account-id must be a 12-digit AWS account ID",
            file=sys.stderr,
        )
        return 1
    control_account_id = args.control_account_id
    if not control_account_id and not principals and args.catalog:
        try:
            control_account_id = _control_account_id_from_catalog(args.catalog)
        except Exception as exc:
            print(
                f"Error: cannot derive control account from catalog "
                f"{args.catalog}: {exc}",
                file=sys.stderr,
            )
            return 1
    if not control_account_id and not principals:
        print(
            "Error: provide --control-account-id, --principal, or --catalog",
            file=sys.stderr,
        )
        return 1
    if args.json and not args.yes:
        print("Error: --json requires --yes for non-interactive apply", file=sys.stderr)
        return 1

    session, s3_client, region, _resolved_profile = bucket_lib.resolve_bucket_session(
        args.bucket_name,
        args.profile,
        assume_yes=args.yes,
        no_prompt=bool(args.json and args.profile),
        output=sys.stderr,
    )
    if session is None:
        return 1
    sns_client = session.client("sns", region_name=region)
    sqs_client = session.client("sqs", region_name=region)
    lambda_client = session.client("lambda", region_name=region)
    owning_account = _get_session_account_id(session)
    plan = bucket_lib.build_bucket_preparation_plan(
        args.bucket_name,
        region,
        owning_account,
        control_account_id=control_account_id,
        principals=principals or None,
        s3_client=s3_client,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )

    if args.dry_run:
        _print_bucket_preparation_plan(plan)
        return 0
    if not args.yes and not _confirm_bucket_preparation(plan):
        print("Aborted.")
        return 1

    bucket_lib.apply_bucket_preparation(
        plan,
        s3_client=s3_client,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )
    if args.json:
        print(json.dumps(plan.handoff(), indent=2))
    else:
        print(f"Prepared s3://{plan.bucket} for Quilt access.")
        print(f"SNS notifications: {plan.sns_topic_arn}")
        print(
            "Catalog operator next step: "
            f"quiltx bucket add {plan.bucket} --no-preflight --catalog <catalog>"
        )
    return 0


@stack_lib.catalog_command
def _cmd_add(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    try:
        no_preflight = bool(args.no_preflight or _env_flag("QUILTX_NO_PREFLIGHT"))
        if (
            getattr(args, "no_prompt", False)
            and not getattr(args, "yes", False)
            and not no_preflight
        ):
            print(
                "Error: --no-prompt requires --yes (or --no-preflight) to avoid interactive prompts.",
                file=sys.stderr,
            )
            return 1

        principals, show_guidance = _resolve_principals_arg(args.principal)
        if show_guidance:
            _print_principal_guidance()
            return 0
        for principal in principals:
            if not principal.startswith("arn:aws:iam::"):
                print(
                    f"Error: --principal must be an IAM role ARN, got {principal!r}",
                    file=sys.stderr,
                )
                return 1

        if no_preflight:
            return _cmd_add_no_preflight(stack, args)

        catalog_name = stack.catalog_name
        stack_payload = _ensure_stack_payload(stack)
        control_account_id = _load_control_account_id(stack_payload)
        effective_principals = principals or [f"arn:aws:iam::{control_account_id}:root"]
        principal_source = "--principal" if principals else "account root (default)"
        stack_name = _stack_payload_value(stack_payload, "stack_name", "") or None
        control_region = _stack_payload_value(stack_payload, "region", "unknown")
        catalog_url = stack.catalog_url

        session, s3_client, bucket_region, resolved_profile = (
            bucket_lib.resolve_bucket_session(
                args.bucket_name,
                args.profile,
                assume_yes=args.yes,
                no_prompt=getattr(args, "no_prompt", False),
            )
        )
        if session is None:
            return 1
        args.profile = resolved_profile
        sns_client = session.client("sns", region_name=bucket_region)
        sqs_client = session.client("sqs", region_name=bucket_region)
        lambda_client = session.client("lambda", region_name=bucket_region)

        existing_bucket = stack.admin.buckets.get(args.bucket_name)
        prior_title = (
            getattr(existing_bucket, "title", None)
            if existing_bucket is not None
            else None
        )
        force_reregister = existing_bucket is not None and args.force
        if force_reregister:
            print(
                f"Bucket {args.bucket_name}: already registered in Quilt; "
                "will remove and re-add after AWS preparation (--force) so Quilt "
                "re-subscribes SQS."
            )
        elif existing_bucket is not None:
            print(
                f"Bucket {args.bucket_name}: already registered in Quilt; "
                "reapplying access plumbing (S3 policy / SNS / principals). "
                "Use --force to also remove and re-add the catalog "
                "registration so Quilt re-subscribes SQS."
            )

        data_account_id = _get_session_account_id(session)
        plan = bucket_lib.build_bucket_preparation_plan(
            args.bucket_name,
            bucket_region,
            data_account_id,
            control_account_id=control_account_id,
            principals=principals or None,
            s3_client=s3_client,
            sns_client=sns_client,
            sqs_client=sqs_client,
            lambda_client=lambda_client,
        )

        if args.dry_run:
            _print_dry_run_plan(
                catalog_name,
                catalog_url,
                stack_name,
                control_account_id,
                effective_principals,
                principal_source,
                control_region,
                args.profile,
                plan,
            )
            return 0

        if not args.yes and not _confirm_bucket_add(
            catalog_name,
            catalog_url,
            stack_name,
            control_account_id,
            effective_principals,
            principal_source,
            control_region,
            args.profile,
            plan,
        ):
            print("Aborted.")
            return 1

        bucket_lib.apply_bucket_preparation(
            plan,
            s3_client=s3_client,
            sns_client=sns_client,
            sqs_client=sqs_client,
            lambda_client=lambda_client,
        )
        sns_topic_arn = plan.sns_topic_arn

        bucket_title = args.title or prior_title or args.bucket_name
        if force_reregister:
            stack.admin.buckets.remove(args.bucket_name)
            existing_bucket = None
        if existing_bucket is None:
            stack.admin.buckets.add(
                name=args.bucket_name,
                title=bucket_title,
                sns_notification_arn=sns_topic_arn,
            )
            print(f"Registered bucket {args.bucket_name} as {bucket_title}.")
        else:
            print(
                f"Bucket {args.bucket_name} already registered as "
                f"{bucket_title}; access plumbing reapplied."
            )
        print(f"SNS notifications: {sns_topic_arn}")
        if args.no_test:
            print(
                f"Run `quiltx bucket test {args.bucket_name}` to verify registration and access."
            )
            return 0
        print()
        return _verify_bucket_registration_and_access(
            stack,
            args.bucket_name,
            control_account_id=control_account_id,
        )
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        _print_exception(exc)
        return 1


def _cmd_add_no_preflight(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    existing_bucket = stack.admin.buckets.get(args.bucket_name)
    prior_title = (
        getattr(existing_bucket, "title", None) if existing_bucket is not None else None
    )
    bucket_title = args.title or prior_title or args.bucket_name
    if args.dry_run:
        _print_no_preflight_dry_run(stack, args.bucket_name, bucket_title)
        return 0

    if existing_bucket is not None and args.force:
        print(
            f"Bucket {args.bucket_name}: already registered in Quilt; "
            "removing and re-adding (--force) via GraphQL only."
        )
        stack.admin.buckets.remove(args.bucket_name)
    elif existing_bucket is not None:
        print(
            f"Bucket {args.bucket_name}: already registered in Quilt; "
            "local preflight/setup skipped."
        )
        return 0

    try:
        result = bucket_lib.add_bucket_without_preflight(
            stack,
            args.bucket_name,
            title=bucket_title,
        )
    except bucket_lib.BucketAddError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if result.already_registered:
        print(
            f"Bucket {args.bucket_name}: already registered in Quilt; "
            "local preflight/setup skipped."
        )
    else:
        print(
            f"Registered bucket {result.bucket} as {result.title} "
            "via GraphQL only; local AWS preflight/setup skipped."
        )
    print(
        f"Run `quiltx bucket test {args.bucket_name}` to verify registration and access."
    )
    return 0


@stack_lib.catalog_command
def _cmd_remove(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    try:
        existing = stack.admin.buckets.get(args.bucket_name)
        if existing is None:
            print(f"Bucket {args.bucket_name}: not registered in Quilt; nothing to do.")
            return 0

        if not args.yes:
            reply = (
                input(
                    f"Remove bucket {args.bucket_name} from the Quilt catalog? [y/N] "
                )
                .strip()
                .lower()
            )
            if reply not in ("y", "yes"):
                print("Aborted.")
                return 1

        stack.admin.buckets.remove(args.bucket_name)
        print(f"Removed bucket {args.bucket_name} from the Quilt catalog.")
        print(
            "Note: S3 bucket policy, SNS topic, and bucket notifications were left "
            "in place."
        )
        return 0
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        _print_exception(exc)
        return 1


@stack_lib.catalog_command
def _cmd_list(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    try:
        buckets = stack.admin.buckets.list()
        console = Console()
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Name", style="green")
        table.add_column("Title")
        table.add_column("SNS Topic")
        table.add_column("Prefixes")
        for bucket in buckets:
            table.add_row(
                bucket.name,
                bucket.title,
                bucket.sns_notification_arn or "",
                ", ".join(bucket.prefixes or []),
            )
        console.print(table)
        return 0
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        _print_exception(exc)
        return 1


def _cmd_profile(args: argparse.Namespace) -> int:
    profiles = list(boto3.Session().available_profiles)
    if not profiles:
        print("No AWS profiles found.", file=sys.stderr)
        return 1

    if args.bucket_name is None:
        for name in profiles:
            print(name)
        return 0

    match = bucket_lib.find_profile_for_bucket(args.bucket_name, profiles)
    if match is None:
        print(
            f"No configured profile can access bucket {args.bucket_name!r}.",
            file=sys.stderr,
        )
        return 1
    print(match)
    return 0


@stack_lib.catalog_command
def _cmd_test(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    return _verify_bucket_registration_and_access(stack, args.bucket_name)


def _verify_bucket_registration_and_access(
    stack: stack_lib.Catalog, bucket_name: str, *, control_account_id: str | None = None
) -> int:
    from quiltx.quilt3_facade import make_bucket

    bucket_uri = f"s3://{bucket_name}"
    registered = None
    stage = "registration lookup"
    try:
        registered = next(
            (
                bucket
                for bucket in stack.admin.buckets.list()
                if bucket.name == bucket_name
            ),
            None,
        )
        if registered is None:
            raise ValueError(f"{bucket_name} is not registered in Quilt")

        # Direct S3 access check (b.ls()) intentionally skipped: it ran with
        # the user's locally-cached Quilt STS credentials, which may be stale
        # or scoped by a role that doesn't grant access to this bucket. That
        # produced false-negative AccessDenied errors after legitimate
        # bucket-add operations. See issue tracker for "stale credentials
        # prevent direct verification".

        stage = "search index probe"
        # Confirm the catalog's search index actually has entries for this
        # bucket — proves the SNS -> SQS subscription wiring is live.
        # Retry briefly since the initial scan can lag a freshly added bucket.
        import time as _time

        b: Any = make_bucket(bucket_uri)
        results: list[Any] = []
        for attempt in range(6):
            results = b.search("*", limit=1)
            if results:
                break
            if attempt < 5:
                _time.sleep(10)
        if not results:
            raise RuntimeError(
                "search index returned 0 results after ~60s; SNS "
                "subscription or initial scan has not indexed this bucket yet"
            )

        print(f"OK: {bucket_name} is registered in Quilt as {registered.title}")
        print(f"OK: search index is populated ({len(results)}+ result[s])")
        return 0
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        control_line = (
            f"  - Quilt control account: {control_account_id}"
            if control_account_id
            else "  - Quilt control account: unknown"
        )
        registered_tag = "yes" if registered is not None else "no"
        if stage == "search index probe":
            cause = (
                "  - likely cause: bucket's SNS topic is not subscribed to "
                "this stack's SQS queues, or initial scan has not completed"
            )
        else:
            cause = "  - likely cause: registration lookup failed"
        lines = [
            f"FAILED: bucket {bucket_name} verification failed at {stage}.",
            f"  - registered in Quilt: {registered_tag}",
            control_line,
            f"  - error: {exc}",
            cause,
        ]
        print("\n".join(lines), file=sys.stderr)
        return 1


def _load_control_account_id(stack_payload: Mapping[str, Any] | None) -> str:
    if not stack_payload:
        raise ValueError(
            "No cached stack metadata found. Run 'quiltx catalog stack <dns>' first."
        )
    account_id = stack_payload.get("account_id")
    if not account_id:
        raise ValueError(
            "Cached stack metadata is missing account_id. Run 'quiltx catalog stack <dns>' first."
        )
    return str(account_id)


def _stack_payload_value(
    stack_payload: Mapping[str, Any] | None, key: str, default: str
) -> str:
    if not stack_payload:
        return default
    value = stack_payload.get(key)
    if not value:
        return default
    return str(value)


def _resolve_principals_arg(
    raw: list[str] | None,
) -> tuple[list[str], bool]:
    """Parse --principal values into a list of ARNs.

    Returns (principals, show_guidance). show_guidance is True when the user
    passed a bare --principal with no value.
    """
    if not raw:
        return [], False
    principals: list[str] = []
    show_guidance = False
    for item in raw:
        if item == "":
            show_guidance = True
            continue
        for part in item.split(","):
            part = part.strip()
            if part:
                principals.append(part)
    return principals, show_guidance


def _print_principal_guidance() -> None:
    print(
        "The --principal flag sets the IAM ARN(s) granted cross-account access in "
        "the bucket policy.\n"
        "\n"
        "Default (flag omitted): the entire control account root\n"
        "  arn:aws:iam::<CONTROL-ACCOUNT-ID>:root\n"
        "\n"
        "To narrow access, pass one or more role ARNs (repeatable, or comma-\n"
        "separated). Quilt does not publish an official list of roles for the\n"
        "bucket policy; the documented principal is the control account root.\n"
        "If you choose to restrict, inspect your Quilt CloudFormation stack's\n"
        "IAM resources and select the roles appropriate for your use case.\n"
        "See: https://docs.quilt.bio/quilt-platform-administrator/crossaccount\n"
        "\n"
        "Example:\n"
        "  quiltx bucket add my-bucket \\\n"
        "      --principal arn:aws:iam::123:role/<stack>-SomeRole-XXXX"
    )


def _get_session_account_id(session: boto3.Session) -> str:
    return str(session.client("sts").get_caller_identity()["Account"])


def _confirm_bucket_add(
    catalog_name: str,
    catalog_url: str,
    stack_name: str | None,
    control_account_id: str,
    principals: list[str],
    principal_source: str,
    control_region: str,
    profile: str | None,
    plan: bucket_lib.BucketPreparationPlan,
) -> bool:
    console = Console(width=120)
    _print_context_table(
        console,
        "Bucket add confirmation",
        catalog_name,
        catalog_url,
        stack_name,
        control_account_id,
        principals,
        principal_source,
        control_region,
        plan.bucket,
        plan.region,
        plan.owning_account,
        profile,
        plan.sns_topic_arn if plan.topic_exists else None,
    )
    if not plan.topic_exists:
        console.print(
            f"\n[yellow]WARNING:[/yellow] no existing SNS topic found; "
            f"a new topic will be created: {plan.sns_topic_arn}"
        )
    response = input("Continue? [y/N]: ").strip().lower()
    return response in {"y", "yes"}


def _print_dry_run_plan(
    catalog_name: str,
    catalog_url: str,
    stack_name: str | None,
    control_account_id: str,
    principals: list[str],
    principal_source: str,
    control_region: str,
    profile: str | None,
    plan: bucket_lib.BucketPreparationPlan,
) -> None:
    console = Console(width=120)
    _print_context_table(
        console,
        "Bucket add dry-run",
        catalog_name,
        catalog_url,
        stack_name,
        control_account_id,
        principals,
        principal_source,
        control_region,
        plan.bucket,
        plan.region,
        plan.owning_account,
        profile,
        plan.sns_topic_arn if plan.topic_exists else None,
    )
    if not plan.topic_exists:
        console.print(
            f"\n[yellow]WARNING:[/yellow] no existing SNS topic found; "
            f"a new topic will be created: {plan.sns_topic_arn}"
        )
    _print_plan_documents(console, plan)


def _print_no_preflight_dry_run(
    stack: stack_lib.Catalog, bucket_name: str, bucket_title: str
) -> None:
    console = Console(width=120)
    table = Table(
        title="Bucket add dry-run (--no-preflight)",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=False,
    )
    table.add_column("Resource", style="green", overflow="fold")
    table.add_column("Action", overflow="fold")
    table.add_row(stack.catalog_name, "use catalog API key for GraphQL bucketAdd")
    table.add_row(f"s3://{bucket_name}", f"register as {bucket_title!r}")
    console.print(table)
    print()
    print("Skipped local AWS preflight/setup:")
    for item in (
        "GetBucketLocation",
        "GetBucketPolicy / PutBucketPolicy",
        "SNS topic creation and policy configuration",
        "bucket-notification configuration",
        "post-add verification (--no-preflight implies --no-test)",
    ):
        print(f"  - {item}")


def _print_context_table(
    console: Console,
    title: str,
    catalog_name: str,
    catalog_url: str,
    stack_name: str | None,
    control_account_id: str,
    principals: list[str],
    principal_source: str,
    control_region: str,
    bucket_name: str,
    bucket_region: str,
    data_account_id: str,
    profile: str | None,
    sns_topic_arn: str | None,
) -> None:
    context_table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=False,
    )
    context_table.add_column("Resource", style="green", overflow="fold")
    context_table.add_column("Account", no_wrap=True)
    context_table.add_column("Region", no_wrap=True)
    context_table.add_column("Source", overflow="fold")
    context_table.add_row(
        catalog_name,
        control_account_id,
        control_region,
        catalog_url,
    )
    if stack_name:
        context_table.add_row(
            stack_name,
            control_account_id,
            control_region,
            "cached stack.json",
        )
    for principal in principals:
        context_table.add_row(
            principal,
            control_account_id,
            control_region,
            principal_source,
        )
    context_table.add_row(
        f"s3://{bucket_name}",
        data_account_id,
        bucket_region,
        f"AWS profile {profile or '<default>'}",
    )
    if sns_topic_arn:
        context_table.add_row(
            sns_topic_arn,
            data_account_id,
            bucket_region,
            _sns_topic_source(bucket_name, sns_topic_arn),
        )
    else:
        context_table.add_row(
            (
                f"arn:aws:sns:{bucket_region}:{data_account_id}:"
                f"{bucket_lib._sns_topic_name(bucket_name)}"
            ),
            data_account_id,
            bucket_region,
            "create SNS topic",
        )
    console.print(context_table)


def _sns_topic_source(bucket_name: str, sns_topic_arn: str) -> str:
    topic_name = sns_topic_arn.rsplit(":", 1)[-1]
    if topic_name == bucket_lib._sns_topic_name(bucket_name):
        return "reuse quiltx SNS topic"
    if topic_name.startswith(f"{bucket_name}-QuiltNotifications-"):
        return "reuse Quilt SNS topic"
    return "reuse existing SNS topic"


def _print_json(console: Console, payload: Mapping[str, Any]) -> None:
    console.print(
        Syntax(
            json.dumps(payload, indent=2, sort_keys=True),
            "json",
            background_color="default",
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
