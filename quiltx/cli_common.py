"""Shared argparse helpers for quiltx CLI tools."""

from __future__ import annotations

import argparse


def add_catalog_args(
    parser: argparse.ArgumentParser, *, auth_required: bool = True
) -> None:
    """Add standard catalog arguments to *parser*.

    Always adds:
        --catalog   Catalog DNS name or https:// URL  (dest="catalog")
        --no-prompt Suppress interactive prompts       (store_true)
        --verbose   Enable verbose output              (store_true)

    When auth_required is True also adds:
        --api-key   Catalog API key (qk_...)
    """
    parser.add_argument(
        "--catalog",
        dest="catalog",
        metavar="DNS_OR_URL",
        help="Catalog DNS name or https:// URL (e.g. example.quiltdata.com).",
    )
    if auth_required:
        parser.add_argument(
            "--api-key",
            dest="api_key",
            metavar="QK_...",
            help="Catalog API key (qk_...). Also accepted via QUILTX_API_KEY.",
        )
        parser.add_argument(
            "--insecure",
            action="store_true",
            default=False,
            help=(
                "Allow http:// transport to localhost for testing local "
                "catalog builds. Refused for any non-localhost target. "
                "Never persisted."
            ),
        )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        default=False,
        help="Suppress interactive prompts; fail instead.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose output.",
    )
