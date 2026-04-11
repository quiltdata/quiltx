"""Helpers for running Quilt ECS tasks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import boto3
from botocore.exceptions import WaiterError

from quiltx import stack as stack_lib
from quiltx.utils import get_hostname


@dataclass(frozen=True)
class MigrationResult:
    task_arn: str
    exit_code: int | None
    stopped_reason: str | None
    stop_code: str | None


class MigrationLaunchError(RuntimeError):
    """Raised when ECS returns launch failures instead of a task."""

    def __init__(self, failures: list[dict[str, str]]):
        self.failures = failures
        parts = []
        for failure in failures:
            detail = " / ".join(
                value
                for value in (
                    failure.get("arn"),
                    failure.get("reason"),
                    failure.get("detail"),
                )
                if value
            )
            if detail:
                parts.append(detail)
        super().__init__(", ".join(parts) or "Migration task failed to launch")


def _coerce_str(value: object | None) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _ecs_resources(
    stack_payload: Mapping[str, object] | None,
) -> list[Mapping[str, object]]:
    if not stack_payload:
        return []
    resources = stack_payload.get("ecs_resources")
    if not isinstance(resources, list):
        return []
    return [resource for resource in resources if isinstance(resource, dict)]


def _cluster_from_stack_payload(stack_payload: Mapping[str, object]) -> str:
    clusters = [
        resource
        for resource in _ecs_resources(stack_payload)
        if resource.get("resource_type") == "AWS::ECS::Cluster"
    ]
    if len(clusters) == 1:
        cluster = _coerce_str(clusters[0].get("physical_id"))
        if cluster:
            return cluster

    stack_name = _coerce_str(stack_payload.get("stack_name"))
    if stack_name:
        for cluster_resource in clusters:
            physical_id = _coerce_str(cluster_resource.get("physical_id"))
            if physical_id == stack_name:
                return physical_id

    raise ValueError(
        "Could not determine ECS cluster from cached stack payload. Run 'quiltx stack cfn' first."
    )


def find_migration_task_def(ecs_client: Any, stack_name: str) -> str:
    response = ecs_client.list_task_definitions(
        familyPrefix=f"{stack_name}-registry-migration",
        sort="DESC",
    )
    task_definition_arns = response.get("taskDefinitionArns", [])
    if not task_definition_arns:
        raise ValueError(f"No migration task definition found for stack '{stack_name}'")
    return str(task_definition_arns[0])


def get_network_config(
    ecs_client: Any, cluster: str, stack_payload: Mapping[str, object]
) -> dict[str, object]:
    registry_service: str | None = None

    for resource in _ecs_resources(stack_payload):
        if resource.get("resource_type") != "AWS::ECS::Service":
            continue
        logical_id = _coerce_str(resource.get("logical_id")) or ""
        physical_id = _coerce_str(resource.get("physical_id"))
        if not physical_id:
            continue
        if logical_id == "RegistryService":
            registry_service = physical_id
            break
        if registry_service is None and "registry" in logical_id.lower():
            registry_service = physical_id

    if not registry_service:
        raise ValueError(
            "Could not find RegistryService in cached stack payload. Run 'quiltx stack cfn' first."
        )

    response = ecs_client.describe_services(
        cluster=cluster, services=[registry_service]
    )
    services = response.get("services", [])
    if not services:
        raise ValueError(f"Registry service '{registry_service}' was not found in ECS")

    network_config = services[0].get("networkConfiguration")
    if not isinstance(network_config, dict):
        raise ValueError(
            f"Registry service '{registry_service}' is missing a network configuration"
        )
    return dict(network_config)


def run_migration(
    ecs_client: Any,
    cluster: str,
    task_def: str,
    network_config: Mapping[str, object],
) -> dict[str, object]:
    response = ecs_client.run_task(
        cluster=cluster,
        taskDefinition=task_def,
        launchType="FARGATE",
        networkConfiguration=dict(network_config),
        propagateTags="TASK_DEFINITION",
        enableECSManagedTags=True,
    )

    failures = response.get("failures", [])
    if failures:
        raise MigrationLaunchError(
            [
                {
                    "arn": str(failure.get("arn") or ""),
                    "reason": str(failure.get("reason") or ""),
                    "detail": str(failure.get("detail") or ""),
                }
                for failure in failures
                if isinstance(failure, dict)
            ]
        )

    tasks = response.get("tasks", [])
    if not tasks:
        raise ValueError("ECS did not return a migration task")
    return dict(tasks[0])


def wait_for_task(ecs_client: Any, cluster: str, task_arn: str) -> MigrationResult:
    waiter = ecs_client.get_waiter("tasks_stopped")
    try:
        waiter.wait(
            cluster=cluster,
            tasks=[task_arn],
            WaiterConfig={"Delay": 10, "MaxAttempts": 60},
        )
    except WaiterError as exc:
        raise RuntimeError(
            f"Timed out waiting for migration task to stop: {task_arn}"
        ) from exc

    response = ecs_client.describe_tasks(cluster=cluster, tasks=[task_arn])
    tasks = response.get("tasks", [])
    if not tasks:
        raise ValueError(f"Migration task not found after wait: {task_arn}")

    task = tasks[0]
    containers = task.get("containers", [])
    selected = next(
        (
            container
            for container in containers
            if isinstance(container, dict)
            and container.get("name") == "registry_migration"
        ),
        containers[0] if containers else {},
    )

    exit_code = selected.get("exitCode") if isinstance(selected, dict) else None
    if exit_code is not None:
        exit_code = int(exit_code)

    return MigrationResult(
        task_arn=str(task.get("taskArn") or task_arn),
        exit_code=exit_code,
        stopped_reason=_coerce_str(task.get("stoppedReason")),
        stop_code=_coerce_str(task.get("stopCode")),
    )


def run_migration_for_catalog(
    catalog: str,
    *,
    wait: bool = True,
    region: str | None = None,
) -> MigrationResult:
    catalog_name = get_hostname(catalog)
    stack_payload = stack_lib.load_stack_payload(catalog_name)
    if not stack_payload:
        raise ValueError(
            f"No cached stack payload found for '{catalog_name}'. Run 'quiltx stack cfn' first."
        )

    stack_name = _coerce_str(stack_payload.get("stack_name"))
    if not stack_name:
        raise ValueError("Cached stack payload is missing stack_name")

    resolved_region = region or _coerce_str(stack_payload.get("region"))
    cluster = _cluster_from_stack_payload(stack_payload)
    ecs_client = boto3.client("ecs", region_name=resolved_region)

    task_def = find_migration_task_def(ecs_client, stack_name)
    network_config = get_network_config(ecs_client, cluster, stack_payload)
    task = run_migration(ecs_client, cluster, task_def, network_config)
    task_arn = _coerce_str(task.get("taskArn"))
    if not task_arn:
        raise ValueError("Migration task response did not include taskArn")

    if not wait:
        return MigrationResult(
            task_arn=task_arn,
            exit_code=None,
            stopped_reason=None,
            stop_code=None,
        )

    return wait_for_task(ecs_client, cluster, task_arn)
