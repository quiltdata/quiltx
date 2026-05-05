"""Forget a catalog's credentials: quiltx catalog forget <dns>."""

from __future__ import annotations

import argparse
import sys

from quiltx.identity import normalize_dns


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog forget",
        description="Delete keyring entry for a catalog (idempotent).",
    )
    parser.add_argument(
        "dns",
        help="DNS name of catalog to forget.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    from quiltx import credentials

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        dns = normalize_dns(args.dns)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    credentials.delete(dns)
    print(f"Forgot {dns}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
