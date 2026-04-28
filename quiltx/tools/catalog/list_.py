"""List known catalogs: quiltx catalog list."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog list",
        description="List known catalogs (keyring entries). Never prints secrets.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    from quiltx import credentials

    parser = build_parser()
    parser.parse_args(argv)  # handles --help

    entries = credentials.catalog_list()
    if not entries:
        print("No catalogs known on this machine.")
        return 0

    for dns, username, last_used in entries:
        last_used_str = last_used.isoformat() if last_used else "unknown"
        print(f"{dns}  (user: {username}, last used: {last_used_str})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
