"""ECS shell tool."""

from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Iterable

import boto3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Open an interactive shell inside a running ECS task."
    )
    parser.add_argument("--cluster", required=True, help="ECS cluster name or ARN.")
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
        "--dry-run",
        action="store_true",
        help="Print the execute-command invocation without running it.",
    )
    return parser


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
        ecs_client = boto3.client("ecs", region_name=args.region)
        task_arn = _select_task(ecs_client, args.cluster, args.task, args.service)
        container = _select_container(
            ecs_client, args.cluster, task_arn, args.container
        )
        cmd = _build_execute_command(
            args.cluster, task_arn, container, args.command, args.region
        )

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
