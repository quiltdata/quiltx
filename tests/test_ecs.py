"""Tests for the ECS shell tool."""

from __future__ import annotations

import boto3
from botocore.stub import Stubber

from quiltx.tools import ecs


def test_select_task_uses_explicit_task() -> None:
    client = boto3.client(
        "ecs",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    assert ecs._select_task(client, "cluster", "task-123", None) == "task-123"


def test_select_task_picks_running_task() -> None:
    client = boto3.client(
        "ecs",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "list_tasks",
        {"taskArns": ["arn:aws:ecs:us-east-1:123:task/abc"]},
        {"cluster": "cluster", "desiredStatus": "RUNNING", "serviceName": "svc"},
    )
    stubber.activate()

    task = ecs._select_task(client, "cluster", None, "svc")
    assert task == "arn:aws:ecs:us-east-1:123:task/abc"

    stubber.deactivate()


def test_select_container_defaults_first() -> None:
    client = boto3.client(
        "ecs",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "describe_tasks",
        {
            "tasks": [
                {
                    "taskArn": "arn:aws:ecs:us-east-1:123:task/abc",
                    "containers": [
                        {"name": "app"},
                        {"name": "sidecar"},
                    ],
                }
            ]
        },
        {
            "cluster": "cluster",
            "tasks": ["arn:aws:ecs:us-east-1:123:task/abc"],
        },
    )
    stubber.activate()

    container = ecs._select_container(
        client, "cluster", "arn:aws:ecs:us-east-1:123:task/abc", None
    )
    assert container == "app"

    stubber.deactivate()


def test_build_execute_command_includes_region() -> None:
    cmd = ecs._build_execute_command(
        "cluster",
        "task-arn",
        "container",
        "/bin/sh",
        "us-east-1",
    )
    assert "--region" in cmd
    assert cmd[0:3] == ["aws", "ecs", "execute-command"]


def test_merge_ecs_defaults_updates_payload() -> None:
    payload = {"stack_name": "stack", "ecs_defaults": {"cluster": "old"}}
    updated = ecs._merge_ecs_defaults(
        payload, "cluster", "service", "container", "/bin/sh"
    )
    defaults = updated.get("ecs_defaults")
    assert isinstance(defaults, dict)
    assert defaults["cluster"] == "cluster"
    assert defaults["service"] == "service"
    assert defaults["container"] == "container"
    assert defaults["command"] == "/bin/sh"


def test_collect_reachability_targets() -> None:
    payload = {
        "catalog_config": {
            "registryUrl": "https://registry.example.com",
            "apiGatewayEndpoint": "https://api.example.com",
            "s3Proxy": "https://s3proxy.example.com",
            "emailServer": "https://email-stage.quiltdata.com",
            "sentryDSN": "https://key@sentry.io/1410550",
            "mixpanelToken": "token",
            "licenseUrl": "https://license.example.com",
        }
    }
    targets = ecs._collect_reachability_targets(payload)
    names = {target["name"] for target in targets}
    assert "registry" in names
    assert "api_gateway" in names
    assert "s3_proxy" in names
    assert "email" in names
    assert "sentry" in names
    assert "mixpanel" in names
    assert "license" in names
