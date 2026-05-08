"""Helpers for running Quilt ECS tasks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

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


@dataclass(frozen=True)
class ServiceStatus:
    cluster: str
    service: str
    desired_count: int
    running_count: int
    pending_count: int
    task_definition: str
    deployments: list[Mapping[str, Any]]
    events: list[Mapping[str, Any]]

    @property
    def stable(self) -> bool:
        primary = [item for item in self.deployments if item.get("status") == "PRIMARY"]
        return (
            len(self.deployments) == 1
            and len(primary) == 1
            and primary[0].get("rolloutState") == "COMPLETED"
            and self.running_count == self.desired_count
            and self.pending_count == 0
        )

    @property
    def failed(self) -> bool:
        return any(item.get("rolloutState") == "FAILED" for item in self.deployments)


@dataclass(frozen=True)
class LogLevelPlan:
    cluster: str
    service: str
    container: str
    current_task_definition: str
    level: str | None
    current_level: str | None
    register_task_definition: Mapping[str, Any]

    @property
    def action(self) -> str:
        return "remove QUILT_LOG_LEVEL" if self.level is None else "set QUILT_LOG_LEVEL"


@dataclass(frozen=True)
class LogLevelResult:
    plan: LogLevelPlan
    task_definition_arn: str
    response: Mapping[str, Any]


def _coerce_str(value: object | None) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _cluster_from_stack_payload(stack_payload: Mapping[str, object]) -> str:
    return stack_lib.require_ecs_cluster(stack_payload)


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
    registry_service = stack_lib.require_registry_service(stack_payload)

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
    catalog_context = stack_lib.Catalog.from_dns(
        catalog_name, source="flag", auth_required=False
    )
    stack_payload = stack_lib.ensure_stack_payload(catalog_context)

    stack_name = stack_lib.require_stack_name(stack_payload)

    resolved_region = region or stack_lib.require_region(stack_payload)
    cluster = stack_lib.require_ecs_cluster(stack_payload)
    ecs_client = stack_lib.aws_client("ecs", stack_payload, region=resolved_region)

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


def describe_service_status(
    ecs_client: Any,
    *,
    cluster: str,
    service: str,
) -> ServiceStatus:
    """Return deployment status for one ECS service."""
    response = ecs_client.describe_services(cluster=cluster, services=[service])
    services = response.get("services", [])
    if not services:
        raise ValueError(f"ECS service '{service}' was not found")
    info = services[0]
    return ServiceStatus(
        cluster=cluster,
        service=service,
        desired_count=int(info.get("desiredCount") or 0),
        running_count=int(info.get("runningCount") or 0),
        pending_count=int(info.get("pendingCount") or 0),
        task_definition=str(info.get("taskDefinition") or ""),
        deployments=[
            item for item in info.get("deployments", []) if isinstance(item, dict)
        ],
        events=[item for item in info.get("events", []) if isinstance(item, dict)],
    )


def _task_definition_registration_args(
    task_definition: Mapping[str, Any],
) -> dict[str, Any]:
    """Return fields accepted by ECS RegisterTaskDefinition."""
    allowed_fields = {
        "family",
        "taskRoleArn",
        "executionRoleArn",
        "networkMode",
        "containerDefinitions",
        "volumes",
        "placementConstraints",
        "requiresCompatibilities",
        "cpu",
        "memory",
        "pidMode",
        "ipcMode",
        "proxyConfiguration",
        "inferenceAccelerators",
        "ephemeralStorage",
        "runtimePlatform",
    }
    return {
        key: value
        for key, value in task_definition.items()
        if key in allowed_fields and value is not None
    }


def _set_container_env(
    container_definition: Mapping[str, Any],
    name: str,
    value: str | None,
) -> dict[str, Any]:
    updated = dict(container_definition)
    env_entries = updated.get("environment") or []
    environment = [
        dict(entry)
        for entry in env_entries
        if isinstance(entry, dict) and entry.get("name") != name
    ]
    if value is not None:
        environment.append({"name": name, "value": value})
    updated["environment"] = environment
    return updated


def _default_log_level_container(container_definitions: list[Any]) -> str | None:
    """Pick the application container for log-level changes."""
    names = [
        definition.get("name")
        for definition in container_definitions
        if isinstance(definition, dict) and isinstance(definition.get("name"), str)
    ]
    for preferred in ("registry",):
        if preferred in names:
            return preferred
    return names[0] if names else None


def _container_env_value(
    container_definition: Mapping[str, Any],
    name: str,
) -> str | None:
    env_entries = container_definition.get("environment") or []
    if not isinstance(env_entries, list):
        return None
    for entry in env_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("name") == name and isinstance(entry.get("value"), str):
            return entry["value"]
    return None


def build_log_level_plan(
    ecs_client: Any,
    *,
    cluster: str,
    service: str,
    level: str | None,
    container: str | None = None,
) -> LogLevelPlan:
    """Build a task-definition update plan for QUILT_LOG_LEVEL."""
    service_response = ecs_client.describe_services(cluster=cluster, services=[service])
    services = service_response.get("services", [])
    if not services:
        raise ValueError(f"Registry service '{service}' was not found in ECS")
    task_definition_arn = services[0].get("taskDefinition")
    if not isinstance(task_definition_arn, str) or not task_definition_arn:
        raise ValueError(f"Registry service '{service}' is missing a task definition")

    task_response = ecs_client.describe_task_definition(
        taskDefinition=task_definition_arn
    )
    task_definition = task_response.get("taskDefinition")
    if not isinstance(task_definition, dict):
        raise ValueError(f"Task definition '{task_definition_arn}' was not found")

    registration_args = _task_definition_registration_args(task_definition)
    container_definitions = registration_args.get("containerDefinitions")
    if not isinstance(container_definitions, list) or not container_definitions:
        raise ValueError("Task definition has no container definitions")

    selected = container
    if selected is None:
        selected = _default_log_level_container(container_definitions)
    if not selected:
        raise ValueError("Could not determine target container")

    updated_containers: list[dict[str, Any]] = []
    found = False
    for definition in container_definitions:
        if not isinstance(definition, dict):
            continue
        if definition.get("name") == selected:
            updated_containers.append(
                _set_container_env(definition, "QUILT_LOG_LEVEL", level)
            )
            found = True
        else:
            updated_containers.append(dict(definition))
    if not found:
        raise ValueError(f"Container '{selected}' not found in task definition")

    registration_args["containerDefinitions"] = updated_containers
    current_container = next(
        item
        for item in container_definitions
        if isinstance(item, dict) and item.get("name") == selected
    )
    return LogLevelPlan(
        cluster=cluster,
        service=service,
        container=selected,
        current_task_definition=task_definition_arn,
        level=level,
        current_level=_container_env_value(current_container, "QUILT_LOG_LEVEL"),
        register_task_definition=registration_args,
    )


def apply_log_level_plan(ecs_client: Any, plan: LogLevelPlan) -> LogLevelResult:
    """Register the planned task definition and update the ECS service."""
    register_response = ecs_client.register_task_definition(
        **dict(plan.register_task_definition)
    )
    new_task_definition = register_response.get("taskDefinition")
    if not isinstance(new_task_definition, dict):
        raise ValueError("ECS did not return the registered task definition")
    new_task_definition_arn = new_task_definition.get("taskDefinitionArn")
    if not isinstance(new_task_definition_arn, str) or not new_task_definition_arn:
        raise ValueError("Registered task definition is missing taskDefinitionArn")

    update_response = ecs_client.update_service(
        cluster=plan.cluster,
        service=plan.service,
        taskDefinition=new_task_definition_arn,
        forceNewDeployment=True,
    )
    return LogLevelResult(
        plan=plan,
        task_definition_arn=new_task_definition_arn,
        response=update_response,
    )


def set_log_level(
    ecs_client: Any,
    *,
    cluster: str,
    service: str,
    level: str | None,
    container: str | None = None,
) -> LogLevelResult:
    """Set or clear QUILT_LOG_LEVEL for an ECS service task definition."""
    plan = build_log_level_plan(
        ecs_client,
        cluster=cluster,
        service=service,
        level=level,
        container=container,
    )
    result = apply_log_level_plan(ecs_client, plan)
    print(
        f"Updated {service} to {result.task_definition_arn} "
        f"with QUILT_LOG_LEVEL={level or '<unset>'}"
    )
    return result
