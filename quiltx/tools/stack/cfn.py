"""Quilt catalog stack discovery tool."""

from __future__ import annotations

import argparse
import sys

import boto3

from quiltx import stack as stack_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx stack cfn",
        description=(
            "Discover and store information about the CloudFormation stack for the configured catalog."
        ),
    )
    parser.add_argument(
        "--catalog-name",
        help="Override catalog name (e.g., example.quiltdata.com)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return _run(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


@stack_lib.catalog_command(auth=False)
def _run(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    try:
        catalog_config = stack_lib.fetch_catalog_config(stack.catalog_url)
        region = stack_lib.fetch_region(stack, catalog_config)

        # Use the simplified API - pass region and let the functions create clients
        stack_info = stack_lib.find_matching_stack(stack, region=region)
        log_groups = stack_lib.list_log_group_resources(
            stack, stack_info["StackName"], region=region
        )
        ecs_resources = stack_lib.list_ecs_resources(
            stack, stack_info["StackName"], region=region
        )
        payload = stack_lib.build_stack_payload(
            stack.catalog_name,
            stack.catalog_url,
            region,
            stack_info,
            log_groups,
            ecs_resources,
            catalog_config,
        )
        output_path = stack_lib.write_stack_payload(stack.catalog_name, payload)

        header = stack_lib.format_stack_header(
            stack.catalog_name,
            {
                "stack_name": stack_info.get("StackName"),
                "region": region,
                "account_id": stack_lib.stack_account_id(stack_info),
            },
        )
        print(header)
        print(f"  Log groups: {len(log_groups)}")
        print(f"  ECS resources: {len(ecs_resources)}")
        print(f"  Outputs: {len(stack_info.get('Outputs', []))}")
        print(f"  Parameters: {len(stack_info.get('Parameters', []))}")
        print(f"\nWrote stack details to {output_path}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
