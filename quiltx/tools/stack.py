"""Quilt catalog stack discovery tool."""

from __future__ import annotations

import argparse
import sys

import boto3

from quiltx import stack as stack_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Discover the CloudFormation stack for the configured Quilt catalog "
            "and store log group resources."
        )
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)

    try:
        import quilt3

        config = quilt3.config()
        if not config:
            raise ValueError("No Quilt catalog configured")

        catalog_url = config.get("navigator_url")
        if not catalog_url:
            raise ValueError("navigator_url missing from Quilt config")

        catalog_name = stack_lib.extract_catalog_name(config)
        catalog_config = stack_lib.fetch_catalog_config(str(catalog_url))
        region = stack_lib.resolve_region(config, catalog_config)

        cfn_client = boto3.client("cloudformation", region_name=region)
        stack_info = stack_lib.find_matching_stack(cfn_client, str(catalog_url))
        log_groups = stack_lib.list_log_group_resources(
            cfn_client, stack_info["StackName"]
        )
        output_path = stack_lib.write_stack_payload(
            catalog_name, str(catalog_url), region, stack_info, log_groups
        )

        print(f"Wrote {len(log_groups)} log groups to {output_path}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
