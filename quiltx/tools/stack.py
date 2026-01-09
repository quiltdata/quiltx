"""Quilt catalog stack discovery tool."""

from __future__ import annotations

import argparse
import sys

import boto3

from quiltx import stack as stack_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Discover and store information about the CloudFormation stack for the configured catalog."
        )
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
        if args.catalog_name:
            # Override path: use provided catalog name
            catalog_name = args.catalog_name
            catalog_url = f"https://{catalog_name}"

            # Fetch catalog config to get region
            catalog_config = stack_lib.fetch_catalog_config(catalog_url)
            region = catalog_config.get("region")
            if not region:
                raise ValueError(
                    f"No region found in catalog config for {catalog_name}"
                )
        else:
            # Default path: use quilt3.config() (existing logic)
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

        stack_name = stack_info.get("StackName", "unknown")
        account_id = stack_lib.stack_account_id(stack_info) or "unknown"
        print(f"Found stack: {stack_name}")
        print(f"  Region: {region}")
        print(f"  Account: {account_id}")
        print(f"  Log groups: {len(log_groups)}")
        print(f"  Outputs: {len(stack_info.get('Outputs', []))}")
        print(f"  Parameters: {len(stack_info.get('Parameters', []))}")
        print(f"\nWrote stack details to {output_path}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
