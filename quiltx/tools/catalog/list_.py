"""Catalog list command (stub — implemented in §3)."""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog list",
        description="List known catalogs (keyring entries).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    print("not yet implemented", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
