"""Default catalog management: quiltx catalog default [<dns>] [--clear]."""

from __future__ import annotations

import argparse
import sys

from quiltx.cli_common import add_catalog_args
from quiltx.identity import normalize_dns


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quiltx catalog default",
        description=(
            "Read, set, or clear the default catalog. When setting a DNS that "
            "has no stored credentials, delegates to `quiltx catalog login` to "
            "mint and store an API key (validating the catalog is reachable)."
        ),
    )
    parser.add_argument(
        "dns",
        nargs="?",
        help="DNS name (or https:// URL) to set as default catalog.",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear the default catalog.",
    )
    add_catalog_args(parser, auth_required=True)
    # The leftover --catalog from add_catalog_args is unused for `default`
    # (the positional `dns` is the target); keep it accepted so users do
    # not get surprised, but ignore if both are present.
    return parser


def main(argv: list[str] | None = None) -> int:
    from quiltx import userconfig

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.clear:
        userconfig.clear_default_catalog()
        print("Default catalog cleared.")
        return 0

    target = args.dns or args.catalog
    if target:
        try:
            dns = normalize_dns(target, insecure=args.insecure)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        from quiltx import credentials

        # B.3: validate by authenticating. If the keyring already has a key
        # we trust it (it was either previously bootstrapped here or pasted
        # via `catalog login --api-key`). If not, delegate to login to mint
        # one — that round-trips the catalog and proves it is reachable.
        if not credentials.has_credentials(dns):
            from quiltx.tools.catalog import login as login_tool

            login_argv = ["--catalog", dns]
            if args.insecure:
                login_argv.append("--insecure")
            if args.no_prompt:
                login_argv.append("--no-prompt")
            if args.verbose:
                login_argv.append("--verbose")
            if args.api_key:
                login_argv.extend(["--api-key", args.api_key])

            print(f"No stored API key for {dns}. Logging in...", file=sys.stderr)
            rc = login_tool.main(login_argv)
            if rc != 0:
                return rc

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
