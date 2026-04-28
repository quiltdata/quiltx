"""Tests for the stack tool."""

from __future__ import annotations

import contextlib
import io
import sys
import types
from datetime import datetime, timezone

import boto3
import pytest
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


def test_resolve_catalog_context_from_flag() -> None:
    ctx = stack.resolve_catalog_context("HTTPS://Example.COM/path")

    assert ctx == stack.Catalog(
        catalog_name="example.com",
        catalog_url="https://example.com",
        source="flag",
    )


def test_resolve_catalog_context_from_global_config(tmp_path, monkeypatch) -> None:
    """Bootstrap: quilt3.config() used when no userconfig default is set."""
    from quiltx import userconfig

    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    fake_quilt3 = types.SimpleNamespace(
        config=lambda: {"navigator_url": "https://example.com"}
    )
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    ctx = stack.resolve_catalog_context()

    assert ctx == stack.Catalog(
        catalog_name="example.com",
        catalog_url="https://example.com",
        source="default",
    )


def test_resolve_catalog_context_env_var(tmp_path, monkeypatch) -> None:
    """QUILTX_CATALOG env var resolves with source='env'."""
    from quiltx import userconfig

    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setenv("QUILTX_CATALOG", "env.example.com")

    ctx = stack.resolve_catalog_context()

    assert ctx.catalog_name == "env.example.com"
    assert ctx.source == "env"


def test_resolve_catalog_context_raises_without_config(tmp_path, monkeypatch) -> None:
    from quiltx import userconfig

    monkeypatch.setattr(userconfig, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.delenv("QUILTX_CATALOG", raising=False)
    fake_quilt3 = types.SimpleNamespace(config=lambda: {})
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    with pytest.raises(ValueError, match="No catalog specified"):
        stack.resolve_catalog_context()


def test_catalog_command_retries_after_auth_failure(monkeypatch) -> None:
    call_count = 0
    login_called = False
    ctx = stack.Catalog(
        catalog_name="example.com",
        catalog_url="https://example.com",
        source="global-config",
    )
    monkeypatch.setattr(stack, "resolve_catalog_context", lambda _catalog=None: ctx)

    @stack.catalog_command
    def guarded(stack_arg: stack.Catalog) -> str:
        nonlocal call_count
        assert stack_arg is ctx
        call_count += 1
        if call_count == 1:
            raise Exception("Authentication failed. Check your credentials or API key.")
        return "ok"

    def _fake_login() -> None:
        nonlocal login_called
        login_called = True

    fake_quilt3 = types.SimpleNamespace(login=_fake_login)
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)

    result = guarded()

    assert result == "ok"
    assert call_count == 2
    assert login_called


def test_catalog_command_does_not_catch_other_errors(monkeypatch) -> None:
    ctx = stack.Catalog(
        catalog_name="example.com",
        catalog_url="https://example.com",
        source="global-config",
    )
    monkeypatch.setattr(stack, "resolve_catalog_context", lambda _catalog=None: ctx)

    @stack.catalog_command
    def guarded(_stack_arg: stack.Catalog) -> None:
        raise ValueError("something else")

    with pytest.raises(ValueError, match="something else"):
        guarded()


def test_find_matching_stack() -> None:
    stack_ctx = stack.Catalog(
        catalog_name="example.com", catalog_url="https://example.com", source="flag"
    )
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

    stack_info = stack.find_matching_stack(stack_ctx, cfn_client=client)
    assert stack_info["StackName"] == "quilt-stack"

    stubber.deactivate()


def test_list_log_group_resources() -> None:
    stack_ctx = stack.Catalog(
        catalog_name="example.com", catalog_url="https://example.com", source="flag"
    )
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

    log_groups = stack.list_log_group_resources(
        stack_ctx, "quilt-stack", cfn_client=client
    )
    assert log_groups == [
        {"logical_id": "LogGroupA", "log_group_name": "/aws/lambda/log-group-a"}
    ]

    stubber.deactivate()


def test_list_ecs_resources() -> None:
    stack_ctx = stack.Catalog(
        catalog_name="example.com", catalog_url="https://example.com", source="flag"
    )
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
                    "LogicalResourceId": "EcsCluster",
                    "PhysicalResourceId": "cluster-name",
                    "ResourceType": "AWS::ECS::Cluster",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
                {
                    "LastUpdatedTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "LogicalResourceId": "SomeOther",
                    "PhysicalResourceId": "other",
                    "ResourceType": "AWS::S3::Bucket",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
                {
                    "LastUpdatedTimestamp": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "LogicalResourceId": "EcsService",
                    "PhysicalResourceId": "service-name",
                    "ResourceType": "AWS::ECS::Service",
                    "ResourceStatus": "CREATE_COMPLETE",
                },
            ]
        },
        {"StackName": "quilt-stack"},
    )
    stubber.activate()

    ecs_resources = stack.list_ecs_resources(
        stack_ctx, "quilt-stack", cfn_client=client
    )
    assert ecs_resources == [
        {
            "logical_id": "EcsCluster",
            "physical_id": "cluster-name",
            "resource_type": "AWS::ECS::Cluster",
        },
        {
            "logical_id": "EcsService",
            "physical_id": "service-name",
            "resource_type": "AWS::ECS::Service",
        },
    ]

    stubber.deactivate()


def test_write_log_groups(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(stack, "user_data_path", lambda *_args, **_kwargs: tmp_path)

    payload = stack.build_stack_payload(
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
        [
            {
                "logical_id": "EcsCluster",
                "physical_id": "cluster-name",
                "resource_type": "AWS::ECS::Cluster",
            }
        ],
        {"registryUrl": "https://registry.example.com"},
    )
    output_path = stack.write_stack_payload("catalog", payload)

    assert output_path.exists()
    content = output_path.read_text()
    assert '"catalog_name": "catalog"' in content
    assert '"account_id": "123456789012"' in content
    assert '"stack_name": "stack"' in content
    assert '"outputs"' in content
    assert '"parameters"' in content
    assert '"ecs_resources"' in content
    assert '"catalog_config"' in content
