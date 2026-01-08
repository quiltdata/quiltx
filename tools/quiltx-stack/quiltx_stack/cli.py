"""CLI for quiltx-stack."""

from __future__ import annotations

import argparse
import traceback


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Print a stack summary.")
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum number of frames to display",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    stack = traceback.extract_stack()[:-1]
    for frame in stack[-args.limit :]:
        print(f"{frame.filename}:{frame.lineno} {frame.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
