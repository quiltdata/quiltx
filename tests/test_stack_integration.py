"""Integration tests for live stack discovery."""

from __future__ import annotations

import os

import boto3
import pytest

from quiltx import stack as stack_lib


@pytest.mark.integration
def test_stack_discovers_nightly_quilttest() -> None:
    if os.environ.get("QUILTX_STACK_INTEGRATION") != "1":
        pytest.skip("Set QUILTX_STACK_INTEGRATION=1 to run live stack test.")

    import quilt3

    config = quilt3.config()
    if not config:
        pytest.skip("No Quilt config available.")

    catalog_url = config.get("navigator_url")
    if catalog_url != "https://nightly.quilttest.com":
        pytest.skip("Configured catalog is not nightly.quilttest.com.")

    catalog_config = stack_lib.fetch_catalog_config(str(catalog_url))
    region = stack_lib.resolve_region(config, catalog_config)

    session = boto3.Session(region_name=region)
    if session.get_credentials() is None:
        pytest.skip("No AWS credentials available.")

    cfn_client = session.client("cloudformation")
    stack_info = stack_lib.find_matching_stack(cfn_client, str(catalog_url))

    assert stack_info["StackName"] == "quilt-staging"

    log_groups = stack_lib.list_log_group_resources(cfn_client, stack_info["StackName"])
    assert log_groups
