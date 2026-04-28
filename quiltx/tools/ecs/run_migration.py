"""CLI for re-running registry migration tasks."""

from __future__ import annotations

import argparse
import json
import sys

import boto3

from quiltx import ecs as ecs_lib
from quiltx.cli_common import add_catalog_args
from quiltx.tools.ecs import shell


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx ecs run-migration",
        description="Re-run the registry migration ECS task for the configured catalog stack.",
    )
    add_catalog_args(parser, auth_required=False)
    parser.add_argument(
        "--region",
        help="AWS region override (defaults to stack payload).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Run migration without prompting for confirmation.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print run_task parameters as JSON without starting the task.",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Start the task and return immediately.",
    )
    return parser


def _format_launch_failures(failures: list[dict[str, str]]) -> str:
    lines = ["Migration launch failed:"]
    for failure in failures:
        parts = [value for value in failure.values() if value]
        lines.append(f"  - {' | '.join(parts)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        catalog_name = shell._resolve_catalog_name(args.catalog)
        payload = shell._load_stack_payload(catalog_name)
        if not payload:
            raise ValueError(
                f"No cached stack payload found for '{catalog_name}'. Run 'quiltx stack cfn' first."
            )

        stack_name = payload.get("stack_name")
        if not isinstance(stack_name, str) or not stack_name:
            raise ValueError("Cached stack payload is missing stack_name")

        region = args.region
        if not region:
            payload_region = payload.get("region")
            if isinstance(payload_region, str):
                region = payload_region

        clusters, _services = shell._extract_ecs_resources(payload)
        cluster = shell._default_cluster_from_resources(clusters, stack_name)
        if not cluster:
            raise ValueError(
                "Could not determine ECS cluster from cached stack payload. Run 'quiltx stack cfn' first."
            )

        ecs_client = boto3.client("ecs", region_name=region)
        task_def = ecs_lib.find_migration_task_def(ecs_client, stack_name)
        network_config = ecs_lib.get_network_config(ecs_client, cluster, payload)

        if args.dry_run:
            print(
                json.dumps(
                    {
                        "cluster": cluster,
                        "taskDefinition": task_def,
                        "launchType": "FARGATE",
                        "networkConfiguration": network_config,
                        "propagateTags": "TASK_DEFINITION",
                        "enableECSManagedTags": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        print(f"Stack:           {stack_name}")
        print(f"Cluster:         {cluster}")
        print(f"Task definition: {task_def}")
        if region:
            print(f"Region:          {region}")
        if not args.yes:
            response = input("\nRun migration? [y/N]: ").strip().lower()
            if response not in {"y", "yes"}:
                print("Aborted.")
                return 1

        task = ecs_lib.run_migration(ecs_client, cluster, task_def, network_config)
        task_arn = task.get("taskArn")
        if not isinstance(task_arn, str) or not task_arn:
            raise ValueError("Migration task response did not include taskArn")

        print(f"Started migration task: {task_arn}")
        if args.no_wait:
            print("Not waiting for completion. Check logs with 'quiltx logs'.")
            return 0

        result = ecs_lib.wait_for_task(ecs_client, cluster, task_arn)
        if result.exit_code == 0:
            print("Migration completed successfully.")
            print("Check logs with 'quiltx logs' if you need task output.")
            return 0

        print(f"Migration failed with exit code {result.exit_code}.", file=sys.stderr)
        if result.stop_code:
            print(f"Stop code: {result.stop_code}", file=sys.stderr)
        if result.stopped_reason:
            print(f"Stopped reason: {result.stopped_reason}", file=sys.stderr)
        print("Check logs with 'quiltx logs' for task output.", file=sys.stderr)
        return 1
    except ecs_lib.MigrationLaunchError as exc:
        print(_format_launch_failures(exc.failures), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
