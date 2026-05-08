"""Quilt ECS tools."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module

from .shell import (
    _build_execute_command as _build_execute_command,
    _collect_reachability_targets as _collect_reachability_targets,
    _default_cluster_from_resources as _default_cluster_from_resources,
    _default_service_from_resources as _default_service_from_resources,
    _extract_ecs_resources as _extract_ecs_resources,
    _merge_ecs_defaults as _merge_ecs_defaults,
    _select_container as _select_container,
    _select_task as _select_task,
)

SUBCOMMANDS = {
    "logs": "quiltx.tools.ecs.logs",
    "run-migration": "quiltx.tools.ecs.run_migration",
    "shell": "quiltx.tools.ecs.shell",
    "status": "quiltx.tools.ecs.status",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx ecs",
        description="Manage Quilt ECS workloads and interactive task access.",
    )
    subparsers = parser.add_subparsers(
        dest="subcommand",
        title="subcommands",
        metavar="SUBCOMMAND",
    )
    subparsers.add_parser(
        "logs",
        help="Display CloudWatch logs for the configured Quilt catalog.",
        add_help=False,
    )
    subparsers.add_parser(
        "shell",
        help="Open an interactive shell inside a running ECS task.",
        add_help=False,
    )
    subparsers.add_parser(
        "status",
        help="Show or wait for the configured catalog ECS service rollout.",
        add_help=False,
    )
    subparsers.add_parser(
        "run-migration",
        help="Re-run the registry migration task for the configured catalog stack.",
        add_help=False,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 1

    args, remaining = parser.parse_known_args(argv)
    if not args.subcommand:
        parser.print_help()
        return 1
    if args.subcommand not in SUBCOMMANDS:
        print(f"Error: Unknown subcommand '{args.subcommand}'", file=sys.stderr)
        return 1

    module = import_module(SUBCOMMANDS[args.subcommand])
    return module.main(remaining)
