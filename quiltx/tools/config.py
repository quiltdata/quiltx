"""Quilt catalog configuration tool."""

from __future__ import annotations

import argparse
import sys

import quiltx


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Show or set the Quilt catalog configured by quilt3."
    )
    parser.add_argument(
        "catalog_url",
        nargs="?",
        help="Catalog URL to configure (e.g., https://open.quiltdata.com). If omitted, shows current configuration.",
    )
    parser.add_argument(
        "--token",
        help="API token for authentication",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if not args.catalog_url:
            # Show the current config without modifying
            import quilt3

            config = quilt3.config()
            if config:
                for key, value in config.items():
                    print(f"{key}: {value}")
            else:
                print("No catalog configured", file=sys.stderr)
                return 1
        else:
            # Configure the catalog
            config_kwargs = {}
            if args.token:
                config_kwargs["token"] = args.token

            config = quiltx.configured_catalog(args.catalog_url, **config_kwargs)

            print(f"Configured catalog: {args.catalog_url}")
            if config:
                for key, value in config.items():
                    print(f"  {key}: {value}")

        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
