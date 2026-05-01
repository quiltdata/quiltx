"""List known catalogs: quiltx catalog list."""

from __future__ import annotations

import argparse
import time
from typing import Mapping

# Spec [05 §7]: "EXPIRES SOON" is < 14 days from expires_at.
_EXPIRES_SOON_WINDOW = 14 * 24 * 60 * 60

_NOW = time.time  # indirection so tests can monkeypatch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog list",
        description="List known catalogs (keyring entries). Never prints secrets.",
    )
    return parser


def _status_for(entry: Mapping[str, object]) -> str:
    expires_at = entry.get("expires_at")
    if not isinstance(expires_at, (int, float)):
        return "UNKNOWN"
    delta = expires_at - _NOW()
    if delta < 0:
        return "EXPIRED"
    if delta < _EXPIRES_SOON_WINDOW:
        return "EXPIRES SOON"
    return "ACTIVE"


def _valid_until_for(entry: Mapping[str, object]) -> str:
    expires_at = entry.get("expires_at")
    if not isinstance(expires_at, (int, float)):
        return "UNKNOWN"
    return time.strftime("%Y-%m-%d", time.gmtime(expires_at))


def _name_for(entry: Mapping[str, object]) -> str:
    name = entry.get("name")
    if isinstance(name, str) and name:
        return name
    return "UNKNOWN"


def main(argv: list[str] | None = None) -> int:
    from quiltx import credentials

    parser = build_parser()
    parser.parse_args(argv)  # handles --help

    entries = credentials.catalog_list()
    if not entries:
        print("No catalogs known on this machine.")
        return 0

    rows = [
        (
            dns,
            _name_for(entry),
            _valid_until_for(entry),
            _status_for(entry),
        )
        for dns, entry in entries
    ]

    headers = ("DNS", "KEY NAME", "VALID UNTIL", "STATUS")
    widths = [max(len(headers[i]), max(len(row[i]) for row in rows)) for i in range(4)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    for row in rows:
        print(fmt.format(*row))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
