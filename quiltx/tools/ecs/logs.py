"""ECS logs CLI: moved under `quiltx ecs` with `--set-level` option."""

from __future__ import annotations

import argparse
from typing import Any

from quiltx.tools import logs as logs_tool
from quiltx import ecs as ecs_lib


def build_parser() -> argparse.ArgumentParser:
    parser = logs_tool.build_parser()
    parser.add_argument(
        "--set-level",
        dest="set_level",
        help="Set the container log level (e.g. DEBUG). Performs a dry-run unless --yes is provided.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Perform the changes instead of a dry-run.",
    )
    return parser


def _run(args: Any) -> int:
    # If set-level provided, call ecs helper and exit
    if getattr(args, "set_level", None):
        # For now, assume a single service derived from catalog payload
        # A full impl would locate the registry service and container name
        service = "registry-service"
        container = None
        dry_run = not bool(getattr(args, "yes", False))
        ecs_lib.set_log_level(service, container, args.set_level, dry_run=dry_run)
        return 0

    # Otherwise, delegate to original logs tool
    return logs_tool._run(args)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
