"""Tests for the ECS shell tool."""

from __future__ import annotations

import boto3
from botocore.stub import Stubber

from quiltx import ecs as ecs_lib
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


def test_default_service_from_resources_prefers_registry() -> None:
    services = [
        {
            "logical_id": "OtherService",
            "physical_id": "other",
            "resource_type": "AWS::ECS::Service",
        },
        {
            "logical_id": "RegistryService",
            "physical_id": "registry",
            "resource_type": "AWS::ECS::Service",
        },
    ]
    assert ecs._default_service_from_resources(services) == "registry"


def test_default_service_from_resources_singleton() -> None:
    services = [
        {
            "logical_id": "OnlyService",
            "physical_id": "only",
            "resource_type": "AWS::ECS::Service",
        }
    ]
    assert ecs._default_service_from_resources(services) == "only"


def test_default_cluster_from_resources_singleton() -> None:
    clusters = [
        {
            "logical_id": "Cluster",
            "physical_id": "cluster-a",
            "resource_type": "AWS::ECS::Cluster",
        }
    ]
    assert ecs._default_cluster_from_resources(clusters) == "cluster-a"


def test_find_migration_task_def() -> None:
    class FakeEcsClient:
        def list_task_definitions(self, *, familyPrefix: str, sort: str):
            assert familyPrefix == "tf-dev-bench-registry-migration"
            assert sort == "DESC"
            return {
                "taskDefinitionArns": [
                    "arn:aws:ecs:us-east-1:123:task-definition/tf-dev-bench-registry-migration:9"
                ]
            }

    task_def = ecs_lib.find_migration_task_def(FakeEcsClient(), "tf-dev-bench")
    assert task_def.endswith(":9")


def test_find_migration_task_def_not_found() -> None:
    class FakeEcsClient:
        def list_task_definitions(self, *, familyPrefix: str, sort: str):
            return {"taskDefinitionArns": []}

    try:
        ecs_lib.find_migration_task_def(FakeEcsClient(), "tf-dev-bench")
    except ValueError as exc:
        assert "No migration task definition" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_get_network_config_prefers_registry() -> None:
    class FakeEcsClient:
        def describe_services(self, *, cluster: str, services: list[str]):
            assert cluster == "tf-dev-bench"
            assert services == ["registry-service"]
            return {
                "services": [
                    {
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-123"],
                                "securityGroups": ["sg-123"],
                            }
                        }
                    }
                ]
            }

    payload = {
        "ecs_resources": [
            {
                "logical_id": "BenchlingService",
                "physical_id": "benchling-service",
                "resource_type": "AWS::ECS::Service",
            },
            {
                "logical_id": "RegistryService",
                "physical_id": "registry-service",
                "resource_type": "AWS::ECS::Service",
            },
        ]
    }

    network_config = ecs_lib.get_network_config(
        FakeEcsClient(), "tf-dev-bench", payload
    )
    awsvpc_config = network_config.get("awsvpcConfiguration")
    assert isinstance(awsvpc_config, dict)
    subnets = awsvpc_config.get("subnets")
    assert subnets == ["subnet-123"]


def test_get_network_config_no_registry() -> None:
    class FakeEcsClient:
        pass

    payload = {
        "ecs_resources": [
            {
                "logical_id": "BenchlingService",
                "physical_id": "benchling-service",
                "resource_type": "AWS::ECS::Service",
            }
        ]
    }

    try:
        ecs_lib.get_network_config(FakeEcsClient(), "tf-dev-bench", payload)
    except ValueError as exc:
        assert "RegistryService" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_run_migration_launch_failure() -> None:
    class FakeEcsClient:
        def run_task(self, **kwargs):
            assert kwargs["cluster"] == "tf-dev-bench"
            return {
                "tasks": [],
                "failures": [
                    {
                        "arn": "arn:aws:ecs:us-east-1:123:service/registry",
                        "reason": "ACCESS_DENIED",
                        "detail": "iam denied",
                    }
                ],
            }

    try:
        ecs_lib.run_migration(
            FakeEcsClient(),
            "tf-dev-bench",
            "task-def-arn",
            {"awsvpcConfiguration": {"subnets": ["subnet-123"]}},
        )
    except ecs_lib.MigrationLaunchError as exc:
        assert exc.failures[0]["reason"] == "ACCESS_DENIED"
    else:
        raise AssertionError("Expected MigrationLaunchError")


def test_run_migration_success() -> None:
    class FakeEcsClient:
        def run_task(self, **kwargs):
            assert kwargs["taskDefinition"] == "task-def-arn"
            assert kwargs["launchType"] == "FARGATE"
            return {
                "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/abc"}],
                "failures": [],
            }

    task = ecs_lib.run_migration(
        FakeEcsClient(),
        "tf-dev-bench",
        "task-def-arn",
        {"awsvpcConfiguration": {"subnets": ["subnet-123"]}},
    )
    task_arn = task.get("taskArn")
    assert isinstance(task_arn, str)
    assert task_arn.endswith("/abc")


def test_set_log_level_dry_run_updates_task_definition(capsys) -> None:
    class FakeEcsClient:
        def describe_services(self, *, cluster: str, services: list[str]):
            assert cluster == "quilt"
            assert services == ["registry-service"]
            return {
                "services": [
                    {
                        "taskDefinition": (
                            "arn:aws:ecs:us-east-1:123:task-definition/quilt-registry:1"
                        )
                    }
                ]
            }

        def describe_task_definition(self, *, taskDefinition: str):
            assert taskDefinition.endswith(":1")
            return {
                "taskDefinition": {
                    "family": "quilt-registry",
                    "networkMode": "awsvpc",
                    "requiresCompatibilities": ["FARGATE"],
                    "cpu": "1024",
                    "memory": "2048",
                    "taskDefinitionArn": taskDefinition,
                    "revision": 1,
                    "status": "ACTIVE",
                    "containerDefinitions": [
                        {
                            "name": "registry",
                            "image": "registry:latest",
                            "environment": [{"name": "EXISTING", "value": "1"}],
                        }
                    ],
                }
            }

    result = ecs_lib.set_log_level(
        FakeEcsClient(),
        cluster="quilt",
        service="registry-service",
        container="registry",
        level="DEBUG",
        dry_run=True,
    )

    register_args = result["registerTaskDefinition"]
    container = register_args["containerDefinitions"][0]
    assert {"name": "QUILT_LOG_LEVEL", "value": "DEBUG"} in container["environment"]
    assert "taskDefinitionArn" not in register_args
    assert '"service": "registry-service"' in capsys.readouterr().out


def test_set_log_level_defaults_to_registry_container() -> None:
    class FakeEcsClient:
        def describe_services(self, *, cluster: str, services: list[str]):
            return {
                "services": [
                    {
                        "taskDefinition": (
                            "arn:aws:ecs:us-east-1:123:task-definition/quilt-registry:1"
                        )
                    }
                ]
            }

        def describe_task_definition(self, *, taskDefinition: str):
            return {
                "taskDefinition": {
                    "family": "quilt-registry",
                    "networkMode": "awsvpc",
                    "requiresCompatibilities": ["FARGATE"],
                    "cpu": "1024",
                    "memory": "2048",
                    "containerDefinitions": [
                        {
                            "name": "registry-tmp-volume-chmod",
                            "image": "init:latest",
                            "environment": [],
                        },
                        {
                            "name": "registry",
                            "image": "registry:latest",
                            "environment": [
                                {"name": "QUILT_LOG_LEVEL", "value": "INFO"}
                            ],
                        },
                        {
                            "name": "nginx",
                            "image": "nginx:latest",
                            "environment": [],
                        },
                    ],
                }
            }

    result = ecs_lib.set_log_level(
        FakeEcsClient(),
        cluster="quilt",
        service="registry-service",
        level="DEBUG",
        dry_run=True,
    )

    containers = result["registerTaskDefinition"]["containerDefinitions"]
    levels = {
        container["name"]: [
            entry["value"]
            for entry in container.get("environment", [])
            if entry.get("name") == "QUILT_LOG_LEVEL"
        ]
        for container in containers
    }
    assert levels["registry"] == ["DEBUG"]
    assert levels["registry-tmp-volume-chmod"] == []


def test_service_status_stable() -> None:
    class FakeEcsClient:
        def describe_services(self, *, cluster: str, services: list[str]):
            return {
                "services": [
                    {
                        "desiredCount": 1,
                        "runningCount": 1,
                        "pendingCount": 0,
                        "taskDefinition": "task-def:1",
                        "deployments": [
                            {
                                "status": "PRIMARY",
                                "rolloutState": "COMPLETED",
                                "desiredCount": 1,
                                "runningCount": 1,
                                "pendingCount": 0,
                            }
                        ],
                        "events": [{"message": "steady state"}],
                    }
                ]
            }

    status = ecs_lib.describe_service_status(
        FakeEcsClient(), cluster="cluster", service="service"
    )

    assert status.stable is True
    assert status.failed is False
