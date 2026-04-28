"""Default catalog management command (stub — implemented in §2)."""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog default",
        description="Read, set, or clear the default catalog.",
    )
    parser.add_argument(
        "dns",
        nargs="?",
        help="DNS name to set as default catalog.",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear the default catalog.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    print("not yet implemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
