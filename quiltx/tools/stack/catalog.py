"""Quilt catalog configuration tool."""

from __future__ import annotations

import argparse
import sys

import quiltx
from quiltx import stack as stack_lib
from quiltx.tls import apply_tls_overrides


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx stack catalog",
        description="Show or set the Quilt catalog configured by quilt3.",
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
    parser.add_argument(
        "--ca-bundle",
        metavar="PATH",
        help=(
            "Path to a PEM file of trusted CA certificates (e.g. a corporate root). "
            "Also exported as SSL_CERT_FILE/REQUESTS_CA_BUNDLE for this process."
        ),
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification. Use only on trusted networks.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        apply_tls_overrides(ca_bundle=args.ca_bundle, insecure=args.insecure)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        if not args.catalog_url:
            # Show the current config without modifying
            try:
                config = quiltx.get_catalog_config()
                ctx = stack_lib.resolve_catalog_context()
                header = stack_lib.current_stack_header(ctx)
                if header:
                    print(header)
                for key, value in config.items():
                    print(f"{key}: {value}")
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
        else:
            # Configure the catalog
            config_kwargs = {}
            if args.token:
                config_kwargs["token"] = args.token

            config = quiltx.set_catalog_url(args.catalog_url, **config_kwargs)

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
