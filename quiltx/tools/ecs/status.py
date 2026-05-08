"""CLI for polling ECS service rollout status."""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table

from quiltx import ecs as ecs_lib
from quiltx import stack as stack_lib
from quiltx.cli_common import add_catalog_args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx ecs status",
        description="Show or wait for the configured catalog ECS service rollout.",
    )
    add_catalog_args(parser, auth_required=False)
    parser.add_argument("--cluster", help="ECS cluster override.")
    parser.add_argument(
        "--service",
        help="ECS service override (defaults to RegistryService from stack payload).",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Poll until the service is stable or failed.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Polling interval in seconds when watching (default 5).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Maximum seconds to wait when watching (default 600).",
    )
    return parser


def render_status(status: ecs_lib.ServiceStatus) -> Table:
    title = "ECS Service Stable" if status.stable else "ECS Service Deploying"
    if status.failed:
        title = "ECS Service Failed"
    table = Table(title=title, show_lines=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Cluster", status.cluster)
    table.add_row("Service", status.service)
    table.add_row("Task definition", status.task_definition)
    table.add_row("Desired", str(status.desired_count))
    table.add_row("Running", str(status.running_count))
    table.add_row("Pending", str(status.pending_count))
    table.add_row("Stable", "yes" if status.stable else "no")

    deployments = Table(title="Deployments", show_lines=False)
    deployments.add_column("Status")
    deployments.add_column("Rollout")
    deployments.add_column("Task definition")
    deployments.add_column("Desired", justify="right")
    deployments.add_column("Running", justify="right")
    deployments.add_column("Pending", justify="right")
    for item in status.deployments:
        deployments.add_row(
            str(item.get("status") or ""),
            str(item.get("rolloutState") or ""),
            str(item.get("taskDefinition") or "").rsplit("/", 1)[-1],
            str(item.get("desiredCount") or 0),
            str(item.get("runningCount") or 0),
            str(item.get("pendingCount") or 0),
        )
    table.add_row("Deployments", deployments)

    if status.events:
        table.add_row("Latest event", str(status.events[0].get("message") or ""))
    return table


def wait_for_stable(
    ecs_client: Any,
    *,
    cluster: str,
    service: str,
    interval: float = 5.0,
    timeout: int = 600,
    console: Console | None = None,
) -> ecs_lib.ServiceStatus:
    """Poll ECS until one service is stable, failed, or timed out."""
    console = console or Console()
    deadline = time.monotonic() + timeout
    status = ecs_lib.describe_service_status(
        ecs_client, cluster=cluster, service=service
    )
    with Live(render_status(status), console=console, refresh_per_second=4) as live:
        while not status.stable and not status.failed:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out waiting for ECS service '{service}' to become stable"
                )
            time.sleep(interval)
            status = ecs_lib.describe_service_status(
                ecs_client, cluster=cluster, service=service
            )
            live.update(render_status(status))
    if status.failed:
        raise RuntimeError(f"ECS service '{service}' deployment failed")
    return status


@stack_lib.catalog_command(auth=False)
def _run(catalog: stack_lib.Catalog, args: argparse.Namespace) -> int:
    payload = stack_lib.ensure_stack_payload(
        catalog,
        announce=lambda message: print(message, file=sys.stderr),
    )
    cluster = args.cluster or stack_lib.require_ecs_cluster(payload)
    service = args.service or stack_lib.require_registry_service(payload)
    ecs_client = stack_lib.aws_client("ecs", payload)
    console = Console()

    if args.watch:
        wait_for_stable(
            ecs_client,
            cluster=cluster,
            service=service,
            interval=args.interval,
            timeout=args.timeout,
            console=console,
        )
        return 0

    status = ecs_lib.describe_service_status(
        ecs_client, cluster=cluster, service=service
    )
    console.print(render_status(status))
    return 0 if status.stable else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
