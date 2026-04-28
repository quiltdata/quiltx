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
        --username  Catalog username
        --password  Catalog password
    """
    parser.add_argument(
        "--catalog",
        dest="catalog",
        metavar="DNS_OR_URL",
        help="Catalog DNS name or https:// URL (e.g. example.quiltdata.com).",
    )
    if auth_required:
        parser.add_argument(
            "--username",
            help="Catalog username for authentication.",
        )
        parser.add_argument(
            "--password",
            help="Catalog password for authentication.",
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
