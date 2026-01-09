"""Quilt catalog logs tool."""

from __future__ import annotations

import argparse
import sys

import boto3

from quiltx import logs as logs_lib
from quiltx import stack as stack_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Display CloudWatch logs for the configured Quilt catalog."
    )
    parser.add_argument(
        "--catalog-name",
        help="Catalog name used in the stack payload path.",
    )
    parser.add_argument(
        "--since",
        help="Start time (ISO 8601 or epoch seconds/millis).",
    )
    parser.add_argument(
        "--until",
        help="End time (ISO 8601 or epoch seconds/millis).",
    )
    parser.add_argument(
        "--minutes",
        type=int,
        help="Look back this many minutes (default 60).",
    )
    parser.add_argument(
        "--hours",
        type=int,
        help="Look back this many hours.",
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Look back this many days.",
    )
    parser.add_argument(
        "--log-group",
        action="append",
        default=[],
        help="Filter to log groups containing this substring (repeatable).",
    )
    parser.add_argument(
        "--filter",
        help="CloudWatch Logs filter pattern.",
    )
    return parser


def _select_log_groups(log_groups: list[str], filters: list[str]) -> list[str]:
    if not filters:
        return log_groups
    selected = []
    for log_group in log_groups:
        if any(filter_text in log_group for filter_text in filters):
            selected.append(log_group)
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.catalog_name:
            catalog_name = args.catalog_name
        else:
            import quilt3

            config = quilt3.config()
            if not config:
                raise ValueError("No Quilt catalog configured")
            catalog_name = stack_lib.extract_catalog_name(config)

        payload = logs_lib.load_stack_payload(catalog_name)

        log_groups = [
            entry.get("log_group_name", "")
            for entry in payload.get("log_groups", [])
            if entry.get("log_group_name")
        ]
        log_groups = _select_log_groups(log_groups, args.log_group)
        if not log_groups:
            raise ValueError("No log groups found in stack payload")

        region = payload.get("region")
        if not region:
            raise ValueError("Region missing from stack payload")

        start_ms, end_ms = logs_lib.resolve_time_range(
            args.since, args.until, args.minutes, args.hours, args.days
        )

        logs_client = boto3.client("logs", region_name=region)
        for event in logs_lib.iter_log_events(
            logs_client, log_groups, start_ms, end_ms, args.filter
        ):
            print(logs_lib.format_event(event))
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
