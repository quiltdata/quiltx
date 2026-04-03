"""Register S3 buckets with the configured Quilt catalog."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from typing import Any, Mapping

import boto3
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from quiltx import bucket as bucket_lib
from quiltx import stack as stack_lib
from quiltx.config import get_catalog_config
from quiltx.utils import get_bucket_region

TEST_OBJECT_PREFIX = ".quiltx/add-bucket-tests"


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

    subparsers.add_parser(
        "list",
        prog="quiltx bucket list",
        help="List buckets registered in the catalog.",
    )

    test_parser = subparsers.add_parser(
        "test",
        prog="quiltx bucket test",
        help="Upload and remove a test object, then print index verification steps.",
    )
    test_parser.add_argument("bucket_name", help="S3 bucket name to test.")
    test_parser.add_argument(
        "--profile",
        help="AWS profile for the data account that owns the bucket.",
    )

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


def _cmd_add(args: argparse.Namespace) -> int:
    try:
        config = get_catalog_config()
        catalog_name = stack_lib.extract_catalog_name(config)
        stack_payload = stack_lib.load_stack_payload(catalog_name)
        control_account_id = _load_control_account_id(stack_payload)
        stack_name = _stack_payload_value(stack_payload, "stack_name", "unknown")
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
            return 0

        bucket_policy = bucket_lib.get_bucket_policy(
            args.bucket_name, s3_client=s3_client
        )
        quilt_statement = bucket_lib.build_quilt_policy_statement(
            args.bucket_name, control_account_id
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
        print(f"Run `quiltx bucket test {args.bucket_name}` to verify indexing.")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


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
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_test(args: argparse.Namespace) -> int:
    test_key = f"{TEST_OBJECT_PREFIX}/{uuid.uuid4().hex}.txt"
    session = boto3.Session(profile_name=args.profile)
    s3_client = session.client("s3")
    try:
        s3_client.put_object(
            Bucket=args.bucket_name,
            Key=test_key,
            Body=b"quiltx bucket test\n",
            ContentType="text/plain",
        )
        print(f"Uploaded s3://{args.bucket_name}/{test_key}")
        print("Waiting briefly before cleanup...")
        time.sleep(2)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        s3_client.delete_object(Bucket=args.bucket_name, Key=test_key)
        print(f"Removed s3://{args.bucket_name}/{test_key}")
        print(
            "Verify bucket indexing in the Quilt catalog UI or search API for "
            f"{test_key}."
        )
        return 0
    except Exception as exc:
        print(
            f"Warning: uploaded test object but failed cleanup: {exc}", file=sys.stderr
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


def _get_session_account_id(session: boto3.Session) -> str:
    return str(session.client("sts").get_caller_identity()["Account"])


def _confirm_bucket_add(
    catalog_name: str,
    catalog_url: str,
    stack_name: str,
    control_account_id: str,
    control_region: str,
    bucket_name: str,
    bucket_region: str,
    data_account_id: str,
    profile: str | None,
    sns_topic_arn: str | None,
) -> bool:
    print(f"About to register bucket {bucket_name}.")
    print(f"Catalog: {catalog_name} ({catalog_url})")
    print(
        f"Control plane: stack {stack_name}, account {control_account_id}, "
        f"region {control_region}"
    )
    print(
        f"Data plane: bucket account {data_account_id}, region {bucket_region}, "
        f"profile {profile or '<default>'}"
    )
    if sns_topic_arn:
        print(f"Existing SNS topic will be reused: {sns_topic_arn}")
    else:
        print("A new SNS topic will be created for bucket notifications.")
    response = input("Continue? [y/N]: ").strip().lower()
    return response in {"y", "yes"}


def _print_dry_run_plan(
    catalog_name: str,
    catalog_url: str,
    stack_name: str,
    control_account_id: str,
    control_region: str,
    bucket_name: str,
    bucket_region: str,
    data_account_id: str,
    profile: str | None,
    merged_policy: Mapping[str, Any],
    sns_topic_arn: str | None,
) -> None:
    console = Console()
    print("Dry-run plan:")
    print(f"  Catalog: {catalog_name} ({catalog_url})")
    print(
        f"  Control plane: stack {stack_name}, account {control_account_id}, "
        f"region {control_region}"
    )
    print(
        f"  Data plane: bucket {bucket_name}, account {data_account_id}, "
        f"region {bucket_region}, profile {profile or '<default>'}"
    )
    print()
    print("Planned bucket policy:")
    _print_json(console, merged_policy)

    if sns_topic_arn:
        print(f"\nPlanned SNS topic: reuse existing {sns_topic_arn}")
        return

    planned_topic_arn = (
        f"arn:aws:sns:{bucket_region}:{data_account_id}:"
        f"{bucket_lib._sns_topic_name(bucket_name)}"
    )
    print(f"\nPlanned SNS topic: create {planned_topic_arn}")
    print("Planned SNS topic policy statement:")
    _print_json(
        console,
        bucket_lib._build_sns_topic_policy_statement(
            bucket_name,
            planned_topic_arn,
            data_account_id,
        ),
    )


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
