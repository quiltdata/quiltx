"""Register S3 buckets with the configured Quilt catalog."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Mapping

import boto3
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from quiltx import bucket as bucket_lib
from quiltx import stack as stack_lib
from quiltx.config import auto_login, get_catalog_config
from quiltx.utils import get_bucket_region


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
        help="Apply changes without prompting for confirmation.",
    )
    add_parser.add_argument(
        "--no-test",
        action="store_true",
        help="Skip the post-add registration/read verification.",
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

    subparsers.add_parser(
        "list",
        prog="quiltx bucket list",
        help="List buckets registered in the catalog.",
    )

    test_parser = subparsers.add_parser(
        "test",
        prog="quiltx bucket test",
        help="Verify the control account can read the bucket (tests cross-account policy).",
    )
    test_parser.add_argument("bucket_name", help="S3 bucket name to test.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.action == "add":
        return _cmd_add(args)
    if args.action == "list":
        return _cmd_list()
    if args.action == "test":
        return _cmd_test(args)

    parser.print_help()
    return 1


def _ensure_stack_payload(
    config: Mapping[str, Any], catalog_name: str
) -> Mapping[str, Any]:
    """Load cached stack payload, or derive a lightweight one from the Quilt session."""
    payload = stack_lib.load_stack_payload(catalog_name)
    if payload is not None:
        return payload

    catalog_url = str(config.get("navigator_url") or f"https://{catalog_name}")
    catalog_config = stack_lib.fetch_catalog_config(catalog_url)
    region = stack_lib.resolve_region(config, catalog_config)

    print(f"Discovering stack for {catalog_name}...")
    try:
        stack_info = stack_lib.find_matching_stack(catalog_url, region=region)
        log_groups = stack_lib.list_log_group_resources(
            stack_info["StackName"], region=region
        )
        stack_lib.write_stack_payload(
            catalog_name,
            catalog_url,
            region,
            stack_info,
            log_groups,
            catalog_config=catalog_config,
        )
        cached = stack_lib.load_stack_payload(catalog_name)
        if cached is not None:
            return cached
    except Exception as exc:
        print(
            f"CloudFormation discovery unavailable ({exc}); "
            "using Quilt session identity for account/region.",
            file=sys.stderr,
        )

    return _lightweight_stack_payload(catalog_name, catalog_url, region, catalog_config)


def _lightweight_stack_payload(
    catalog_name: str,
    catalog_url: str,
    region: str,
    catalog_config: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Build an in-memory stack payload from the Quilt session (no CFN calls)."""
    from quilt3.session import get_boto3_session

    session = get_boto3_session()
    account_id = session.client("sts").get_caller_identity()["Account"]

    return {
        "catalog_name": catalog_name,
        "catalog_url": catalog_url,
        "web_url": catalog_url,
        "region": region,
        "account_id": account_id,
        "stack_name": None,
        "stack_id": None,
        "outputs": [],
        "parameters": [],
        "log_groups": [],
        "ecs_resources": [],
        "catalog_config": dict(catalog_config),
    }


@auto_login
def _cmd_add(args: argparse.Namespace) -> int:
    try:
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

        config = get_catalog_config()
        catalog_name = stack_lib.extract_catalog_name(config)
        stack_payload = _ensure_stack_payload(config, catalog_name)
        control_account_id = _load_control_account_id(stack_payload)
        effective_principals = principals or [f"arn:aws:iam::{control_account_id}:root"]
        principal_source = "--principal" if principals else "account root (default)"
        stack_name = _stack_payload_value(stack_payload, "stack_name", "") or None
        control_region = _stack_payload_value(stack_payload, "region", "unknown")
        catalog_url = str(config.get("navigator_url") or catalog_name)

        session = boto3.Session(profile_name=args.profile)
        s3_client = session.client("s3")
        bucket_region = get_bucket_region(args.bucket_name, s3_client=s3_client)
        sns_client = session.client("sns", region_name=bucket_region)

        from quilt3.admin import buckets as admin_buckets

        existing_bucket = admin_buckets.get(args.bucket_name)
        if existing_bucket is not None:
            print(f"Bucket {args.bucket_name} is already registered.")
            if args.no_test:
                return 0
            return _verify_bucket_registration_and_access(args.bucket_name)

        bucket_policy = bucket_lib.get_bucket_policy(
            args.bucket_name, s3_client=s3_client
        )
        quilt_statement = bucket_lib.build_quilt_policy_statement(
            args.bucket_name,
            control_account_id,
            principals=principals or None,
        )
        merged_policy = bucket_lib.merge_bucket_policy(bucket_policy, quilt_statement)

        sns_topic_arn = bucket_lib.get_bucket_notification_sns(
            args.bucket_name, s3_client=s3_client
        )

        data_account_id = _get_session_account_id(session)

        if args.dry_run:
            _print_dry_run_plan(
                catalog_name,
                catalog_url,
                stack_name,
                control_account_id,
                effective_principals,
                principal_source,
                control_region,
                args.bucket_name,
                bucket_region,
                data_account_id,
                args.profile,
                merged_policy,
                sns_topic_arn,
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
            args.bucket_name,
            bucket_region,
            data_account_id,
            args.profile,
            sns_topic_arn,
        ):
            print("Aborted.")
            return 1

        if sns_topic_arn is None:
            sns_topic_arn = bucket_lib.ensure_sns_topic(
                args.bucket_name,
                bucket_region,
                sns_client=sns_client,
            )

        bucket_lib.configure_sns_topic_policy(
            args.bucket_name,
            sns_topic_arn,
            data_account_id,
            effective_principals,
            sns_client=sns_client,
        )

        bucket_lib.apply_bucket_policy(
            args.bucket_name,
            merged_policy,
            s3_client=s3_client,
        )
        bucket_lib.configure_bucket_notifications(
            args.bucket_name,
            sns_topic_arn,
            s3_client=s3_client,
        )

        bucket_title = args.title or args.bucket_name
        admin_buckets.add(
            name=args.bucket_name,
            title=bucket_title,
            sns_notification_arn=sns_topic_arn,
        )

        print(f"Registered bucket {args.bucket_name} as {bucket_title}.")
        print(f"SNS notifications: {sns_topic_arn}")
        if args.no_test:
            print(
                f"Run `quiltx bucket test {args.bucket_name}` to verify registration and access."
            )
            return 0
        print()
        return _verify_bucket_registration_and_access(args.bucket_name)
    except Exception as exc:
        if "Authentication failed" in str(exc):
            raise
        print(f"Error: {exc}", file=sys.stderr)
        return 1


@auto_login
def _cmd_list() -> int:
    try:
        from quilt3.admin import buckets as admin_buckets

        buckets = admin_buckets.list()
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
        if "Authentication failed" in str(exc):
            raise
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_test(args: argparse.Namespace) -> int:
    return _verify_bucket_registration_and_access(args.bucket_name)


@auto_login
def _verify_bucket_registration_and_access(bucket_name: str) -> int:
    import quilt3
    from quilt3.admin import buckets as admin_buckets

    bucket_uri = f"s3://{bucket_name}"
    try:
        registered = next(
            (bucket for bucket in admin_buckets.list() if bucket.name == bucket_name),
            None,
        )
        if registered is None:
            raise ValueError(f"{bucket_name} is not registered in Quilt")

        b = quilt3.Bucket(bucket_uri)
        # ls() goes through the control account — if the cross-account
        # bucket policy is wrong, this raises AccessDenied.
        list(b.ls())
        print(f"OK: {bucket_name} is registered in Quilt as {registered.title}")
        print(f"OK: control account can read {bucket_uri}")
        return 0
    except Exception as exc:
        if "Authentication failed" in str(exc):
            raise
        print(
            f"Control account cannot read {bucket_uri}: {exc}",
            file=sys.stderr,
        )
        return 1


def _load_control_account_id(stack_payload: Mapping[str, Any] | None) -> str:
    if not stack_payload:
        raise ValueError("No cached stack metadata found. Run 'quiltx stack' first.")
    account_id = stack_payload.get("account_id")
    if not account_id:
        raise ValueError(
            "Cached stack metadata is missing account_id. Run 'quiltx stack' first."
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
    bucket_name: str,
    bucket_region: str,
    data_account_id: str,
    profile: str | None,
    sns_topic_arn: str | None,
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
        bucket_name,
        bucket_region,
        data_account_id,
        profile,
        sns_topic_arn,
    )
    if sns_topic_arn is None:
        planned_topic_arn = (
            f"arn:aws:sns:{bucket_region}:{data_account_id}:"
            f"{bucket_lib._sns_topic_name(bucket_name)}"
        )
        console.print(
            f"\n[yellow]WARNING:[/yellow] no existing SNS topic found; "
            f"a new topic will be created: {planned_topic_arn}"
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
    bucket_name: str,
    bucket_region: str,
    data_account_id: str,
    profile: str | None,
    merged_policy: Mapping[str, Any],
    sns_topic_arn: str | None,
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
        bucket_name,
        bucket_region,
        data_account_id,
        profile,
        sns_topic_arn,
    )
    print()
    print("Planned bucket policy:")
    _print_json(console, merged_policy)

    planned_topic_arn = sns_topic_arn or (
        f"arn:aws:sns:{bucket_region}:{data_account_id}:"
        f"{bucket_lib._sns_topic_name(bucket_name)}"
    )
    if sns_topic_arn is None:
        console.print(
            f"\n[yellow]WARNING:[/yellow] no existing SNS topic found; "
            f"a new topic will be created: {planned_topic_arn}"
        )
    print("\nPlanned SNS topic policy statement:")
    _print_json(
        console,
        {
            "Version": "2012-10-17",
            "Statement": [
                bucket_lib._build_sns_topic_publish_policy_statement(
                    bucket_name,
                    planned_topic_arn,
                    data_account_id,
                ),
                bucket_lib._build_sns_topic_subscribe_policy_statement(
                    planned_topic_arn,
                    principals,
                ),
            ],
        },
    )


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
