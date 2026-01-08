"""Unified CLI for quiltx tools."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module
from typing import NoReturn


# Registry of available tools
TOOLS = {
    "stack": "quiltx.tools.stack",
    "log": "quiltx.tools.log",
}


def list_tools() -> None:
    """List all available tools."""
    print("Available tools:")
    for tool in sorted(TOOLS.keys()):
        print(f"  {tool}")


def run_tool(tool_name: str, args: list[str]) -> int:
    """Run a specific tool with given arguments."""
    if tool_name not in TOOLS:
        print(f"Error: Unknown tool '{tool_name}'", file=sys.stderr)
        print(f"Run 'quiltx --list' to see available tools", file=sys.stderr)
        return 1

    module_path = TOOLS[tool_name]
    try:
        module = import_module(module_path)
        return module.main(args)
    except ImportError as e:
        print(f"Error: Failed to import tool '{tool_name}': {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error running tool '{tool_name}': {e}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="quiltx",
        description="Unified CLI for quiltx tools",
        epilog="Run 'quiltx <tool> --help' for tool-specific help",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available tools",
    )
    parser.add_argument(
        "tool",
        nargs="?",
        help="Tool to run",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to the tool",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle --list flag
    if args.list:
        list_tools()
        return 0

    # Require a tool name if not listing
    if not args.tool:
        parser.print_help()
        return 1

    # Run the specified tool
    return run_tool(args.tool, args.args)


if __name__ == "__main__":
    raise SystemExit(main())
