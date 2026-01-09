"""ECS shell tool."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Mapping

import boto3
from platformdirs import user_data_path
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from quiltx import stack as stack_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Open an interactive shell inside a running ECS task."
    )
    parser.add_argument("--cluster", help="ECS cluster name or ARN.")
    parser.add_argument("--task", help="Task ARN or ID. Defaults to a running task.")
    parser.add_argument(
        "--service",
        help="Service name to filter tasks (optional).",
    )
    parser.add_argument(
        "--container",
        help="Container name to exec into (defaults to first container).",
    )
    parser.add_argument(
        "--command",
        default="/bin/bash",
        help="Shell command to run (default: /bin/bash).",
    )
    parser.add_argument(
        "--region",
        help="AWS region (defaults to AWS SDK configuration).",
    )
    parser.add_argument(
        "--catalog",
        help="Catalog name or URL used to locate stack payload.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the execute-command invocation without running it.",
    )
    return parser


def _stack_payload_path(catalog_name: str) -> Path:
    return user_data_path("quiltx") / catalog_name / "stack.json"


def _load_stack_payload(catalog_name: str) -> Mapping[str, object] | None:
    payload_path = _stack_payload_path(catalog_name)
    if not payload_path.exists():
        return None
    return json.loads(payload_path.read_text())


def _write_stack_payload(catalog_name: str, payload: Mapping[str, object]) -> None:
    payload_path = _stack_payload_path(catalog_name)
    payload_path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def _resolve_catalog_name(catalog_arg: str | None) -> str:
    if catalog_arg:
        return stack_lib.normalize_host(catalog_arg)
    try:
        import quilt3

        config = quilt3.config()
        if config:
            return stack_lib.extract_catalog_name(config)
    except Exception:
        pass
    raise ValueError(
        "No Quilt catalog configured. Run 'quiltx config' or pass --catalog."
    )


def _prompt_resource(
    console: Console,
    title: str,
    resources: list[Mapping[str, str]],
    default_value: str | None,
    allow_skip: bool,
) -> str | None:
    if not resources:
        return None

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Logical Id", style="green")
    table.add_column("Resource Id", style="white")
    table.add_column("Type", style="dim")

    choices = []
    default_choice = None
    for idx, resource in enumerate(resources, 1):
        choice = str(idx)
        choices.append(choice)
        table.add_row(
            choice,
            resource.get("logical_id", ""),
            resource.get("physical_id", ""),
            resource.get("resource_type", ""),
        )
        if default_value and resource.get("physical_id") == default_value:
            default_choice = choice

    if allow_skip:
        choices.append("0")
        table.add_row("0", "(skip)", "", "")

    console.print(f"\n[bold]{title}[/bold]")
    console.print(table)
    prompt_default = default_choice or ("0" if allow_skip else choices[0])
    selection = Prompt.ask("Select", choices=choices, default=prompt_default)
    if allow_skip and selection == "0":
        return None
    selected_index = int(selection) - 1
    return resources[selected_index].get("physical_id")


def _extract_ecs_resources(
    payload: Mapping[str, object] | None,
) -> tuple[list[Mapping[str, str]], list[Mapping[str, str]]]:
    if not payload:
        return [], []
    entries = payload.get("ecs_resources", [])
    if not isinstance(entries, list):
        return [], []
    clusters: list[Mapping[str, str]] = []
    services: list[Mapping[str, str]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        resource_type = item.get("resource_type")
        normalized = {
            "logical_id": str(item.get("logical_id") or ""),
            "physical_id": str(item.get("physical_id") or ""),
            "resource_type": str(resource_type or ""),
        }
        if resource_type == "AWS::ECS::Cluster":
            clusters.append(normalized)
        elif resource_type == "AWS::ECS::Service":
            services.append(normalized)
    return clusters, services


def _merge_ecs_defaults(
    payload: Mapping[str, object],
    cluster: str | None,
    service: str | None,
    container: str | None,
    command: str | None,
) -> dict[str, object]:
    updated = dict(payload)
    defaults_value = updated.get("ecs_defaults")
    defaults = dict(defaults_value) if isinstance(defaults_value, dict) else {}
    if cluster:
        defaults["cluster"] = cluster
    if service is not None:
        defaults["service"] = service
    if container:
        defaults["container"] = container
    if command:
        defaults["command"] = command
    updated["ecs_defaults"] = defaults
    return updated


def _coerce_str(value: object | None) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _select_task(
    ecs_client, cluster: str, task: str | None, service: str | None
) -> str:
    if task:
        return task
    params = {"cluster": cluster, "desiredStatus": "RUNNING"}
    if service:
        params["serviceName"] = service
    response = ecs_client.list_tasks(**params)
    task_arns = response.get("taskArns", [])
    if not task_arns:
        raise ValueError("No running tasks found for the cluster/service")
    return str(task_arns[0])


def _select_container(
    ecs_client, cluster: str, task_arn: str, container: str | None
) -> str:
    response = ecs_client.describe_tasks(cluster=cluster, tasks=[task_arn])
    tasks = response.get("tasks", [])
    if not tasks:
        raise ValueError("Task not found in ECS")
    containers = tasks[0].get("containers", [])
    if not containers:
        raise ValueError("No containers found in ECS task")
    container_names = [str(item.get("name")) for item in containers if item.get("name")]
    if not container_names:
        raise ValueError("No container names found in ECS task")
    if container:
        if container not in container_names:
            raise ValueError(f"Container '{container}' not found in task")
        return container
    return container_names[0]


def _build_execute_command(
    cluster: str,
    task_arn: str,
    container: str,
    command: str,
    region: str | None,
) -> list[str]:
    cmd = [
        "aws",
        "ecs",
        "execute-command",
        "--cluster",
        cluster,
        "--task",
        task_arn,
        "--container",
        container,
        "--interactive",
        "--command",
        command,
    ]
    if region:
        cmd.extend(["--region", region])
    return cmd


def _format_command(cmd: Iterable[str]) -> str:
    return " ".join(cmd)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        console = Console()
        catalog_name = _resolve_catalog_name(args.catalog)
        payload = _load_stack_payload(catalog_name)
        saved_defaults: dict[str, object] = {}
        if payload:
            defaults_value = payload.get("ecs_defaults")
            if isinstance(defaults_value, dict):
                saved_defaults = dict(defaults_value)

        saved_cluster = _coerce_str(saved_defaults.get("cluster"))
        saved_service = _coerce_str(saved_defaults.get("service"))
        saved_container = _coerce_str(saved_defaults.get("container"))
        saved_command = _coerce_str(saved_defaults.get("command"))

        cluster = args.cluster or saved_cluster
        service = args.service or saved_service
        container = args.container or saved_container
        command = args.command or saved_command or "/bin/bash"

        clusters, services = _extract_ecs_resources(payload)
        if not cluster:
            if not payload:
                raise ValueError(
                    "No cluster provided and no stack payload found. Run 'quiltx stack' or pass --cluster."
                )
            cluster = _prompt_resource(
                console,
                "ECS Clusters",
                clusters,
                saved_cluster,
                allow_skip=False,
            )
        if not cluster:
            raise ValueError("No ECS cluster selected")

        if not args.task and service is None and services:
            service = _prompt_resource(
                console,
                "ECS Services",
                services,
                saved_service,
                allow_skip=True,
            )

        ecs_client = boto3.client("ecs", region_name=args.region)
        task_arn = _select_task(ecs_client, cluster, args.task, service)
        container = _select_container(ecs_client, cluster, task_arn, container)
        cmd = _build_execute_command(cluster, task_arn, container, command, args.region)

        if payload:
            updated = _merge_ecs_defaults(payload, cluster, service, container, command)
            _write_stack_payload(catalog_name, updated)

        if args.dry_run:
            print(_format_command(cmd))
            return 0

        result = subprocess.run(cmd, check=False)
        return result.returncode
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
