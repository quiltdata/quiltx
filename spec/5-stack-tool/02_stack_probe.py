from __future__ import annotations

import os
import sys
from pathlib import Path

import boto3

sys.path.append(str(Path(__file__).resolve().parents[2]))

from quiltx import stack


def main() -> int:
    if os.environ.get("QUILTX_STACK_PROBE") != "1":
        print("Skipping stack probe (set QUILTX_STACK_PROBE=1 to run).")
        return 0

    import quilt3

    config = quilt3.config()
    catalog_url = config.get("navigator_url")
    if not catalog_url:
        raise SystemExit("navigator_url not configured")

    catalog_name = stack.extract_catalog_name(config)
    catalog_config = stack.fetch_catalog_config(str(catalog_url))
    region = stack.resolve_region(config, catalog_config)

    session = boto3.Session(region_name=region)
    credentials = session.get_credentials()
    if credentials is None:
        print("No AWS credentials available; skipping.")
        return 0

    cfn_client = session.client("cloudformation")
    stack_info = stack.find_matching_stack(cfn_client, str(catalog_url))
    log_groups = stack.list_log_group_resources(cfn_client, stack_info["StackName"])

    print(f"catalog_name={catalog_name}")
    print(f"stack_name={stack_info['StackName']}")
    print(f"log_group_count={len(log_groups)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
