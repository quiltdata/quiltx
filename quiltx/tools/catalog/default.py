"""Default catalog management: quiltx catalog default [<dns>] [--clear]."""

from __future__ import annotations

import argparse
import sys

from quiltx.identity import normalize_dns


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
    from quiltx import userconfig

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.clear:
        userconfig.clear_default_catalog()
        print("Default catalog cleared.")
        return 0

    if args.dns:
        try:
            dns = normalize_dns(args.dns)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        # §2 spec: verify dns is a known catalog (has credentials).
        # Since credentials.py doesn't exist yet (§3), we skip this check for now
        # and accept any valid DNS. The §3 implementation will wire this guard.
        userconfig.set_default_catalog(dns)
        print(f"Default catalog set to {dns}.")
        return 0

    # Read-only: print current default
    current = userconfig.get_default_catalog()
    if current is None:
        print(
            "No default catalog configured. "
            "Pass --catalog or run `quiltx catalog default <dns>`.",
            file=sys.stderr,
        )
        return 1

    print(current)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
