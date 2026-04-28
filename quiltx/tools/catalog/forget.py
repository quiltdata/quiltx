"""Catalog forget command (stub — implemented in §3)."""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog forget",
        description="Delete keyring entry for a catalog.",
    )
    parser.add_argument(
        "dns",
        help="DNS name of catalog to forget.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    print("not yet implemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
