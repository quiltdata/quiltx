"""Tests for the stack tool."""

from __future__ import annotations

import contextlib
import io
from datetime import datetime, timezone

import boto3
from botocore.stub import Stubber

from quiltx import stack


def test_extract_catalog_name_prefers_catalog_key() -> None:
    config = {"catalog": "example", "navigator_url": "https://ignored.example.com"}
    assert stack.extract_catalog_name(config) == "example"


def test_extract_catalog_name_from_navigator_url() -> None:
    config = {"navigator_url": "https://open.quiltdata.com"}
    assert stack.extract_catalog_name(config) == "open.quiltdata.com"


def test_fetch_catalog_config_uses_opener() -> None:
    payload = b'{"region": "us-east-2"}'

    def opener(url: str):
        assert url == "https://example.com/config.json"
        return contextlib.closing(io.BytesIO(payload))

    config = stack.fetch_catalog_config("https://example.com", opener=opener)
    assert config["region"] == "us-east-2"


def test_find_matching_stack() -> None:
    client = boto3.client(
        "cloudformation",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "describe_stacks",
        {
            "Stacks": [
                {
                    "CreationTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "StackName": "quilt-stack",
                    "StackId": "stack-id",
                    "StackStatus": "CREATE_COMPLETE",
                    "Outputs": [
                        {
                            "OutputKey": "QuiltWebHost",
                            "OutputValue": "example.com",
                        }
                    ],
                }
            ]
        },
        {},
    )
    stubber.activate()

    stack_info = stack.find_matching_stack(client, "https://example.com/")
    assert stack_info["StackName"] == "quilt-stack"

    stubber.deactivate()


def test_list_log_group_resources() -> None:
    client = boto3.client(
        "cloudformation",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "list_stack_resources",
        {
            "StackResourceSummaries": [
                {
                    "LastUpdatedTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "LogicalResourceId": "LogGroupA",
                    "PhysicalResourceId": "/aws/lambda/log-group-a",
                    "ResourceType": "AWS::Logs::LogGroup",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
                {
                    "LastUpdatedTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "LogicalResourceId": "Bucket",
                    "PhysicalResourceId": "bucket-name",
                    "ResourceType": "AWS::S3::Bucket",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
            ]
        },
        {"StackName": "quilt-stack"},
    )
    stubber.activate()

    log_groups = stack.list_log_group_resources(client, "quilt-stack")
    assert log_groups == [
        {"logical_id": "LogGroupA", "log_group_name": "/aws/lambda/log-group-a"}
    ]

    stubber.deactivate()


def test_write_log_groups(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(stack, "user_data_path", lambda *_args, **_kwargs: tmp_path)

    output_path = stack.write_stack_payload(
        "catalog",
        "https://example.com",
        "us-east-1",
        {
            "StackName": "stack",
            "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/stack/abc",
            "Outputs": [
                {"OutputKey": "QuiltWebUrl", "OutputValue": "https://example.com"}
            ],
            "Parameters": [{"ParameterKey": "Env", "ParameterValue": "dev"}],
        },
        [{"logical_id": "LogGroupA", "log_group_name": "/aws/logs"}],
    )

    assert output_path.exists()
    content = output_path.read_text()
    assert '"catalog_name": "catalog"' in content
    assert '"account_id": "123456789012"' in content
    assert '"stack_name": "stack"' in content
    assert '"outputs"' in content
    assert '"parameters"' in content
