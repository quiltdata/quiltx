"""CLI for quiltx-log."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit a structured log line.")
    parser.add_argument("message", help="Log message to emit")
    parser.add_argument(
        "--level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Log level",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    payload = {
        "message": args.message,
        "level": args.level,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
