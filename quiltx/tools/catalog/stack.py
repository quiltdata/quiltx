"""Quilt catalog stack discovery tool."""

from __future__ import annotations

import argparse
import sys


from quiltx import stack as stack_lib
from quiltx.cli_common import add_catalog_args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog stack",
        description=(
            "Discover and store information about the CloudFormation stack for the configured catalog."
        ),
    )
    add_catalog_args(parser, auth_required=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return _run(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


@stack_lib.catalog_command(auth=False, bootstrap=True)
def _run(stack: stack_lib.Catalog, args: argparse.Namespace) -> int:
    try:
        payload = stack_lib.discover_stack_payload(stack)
        output_path = stack_lib.write_stack_payload(stack.catalog_name, payload)

        header = stack_lib.format_stack_header(
            stack.catalog_name,
            {
                "stack_name": payload.get("stack_name"),
                "region": payload.get("region"),
                "account_id": payload.get("account_id"),
            },
        )
        print(header)
        print(f"  Log groups: {len(payload.get('log_groups', []))}")
        print(f"  ECS resources: {len(payload.get('ecs_resources', []))}")
        print(f"  Outputs: {len(payload.get('outputs', []))}")
        print(f"  Parameters: {len(payload.get('parameters', []))}")
        print(f"\nWrote stack details to {output_path}")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
