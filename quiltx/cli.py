"""Unified CLI for quiltx tools."""

from __future__ import annotations

import argparse
import pkgutil
import sys
from importlib import import_module
from pathlib import Path
from typing import NoReturn


def _discover_tools() -> dict[str, str]:
    """Auto-discover tools from the quiltx.tools package."""
    tools = {}
    tools_path = Path(__file__).parent / "tools"

    for module_info in pkgutil.iter_modules([str(tools_path)]):
        if module_info.name != "__init__":
            tools[module_info.name] = f"quiltx.tools.{module_info.name}"

    return tools


# Auto-discovered registry of available tools
TOOLS = _discover_tools()


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


def _get_tool_description(tool_name: str) -> str:
    """Get the description for a tool by importing it and extracting from its parser."""
    try:
        module_path = TOOLS[tool_name]
        module = import_module(module_path)
        if hasattr(module, "build_parser"):
            tool_parser = module.build_parser()
            return tool_parser.description or "No description available"
    except Exception:
        pass
    return "No description available"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="quiltx",
        description="quilt extended toolkit for managing stack deployments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Create subparsers for each tool
    subparsers = parser.add_subparsers(
        dest="tool",
        title="available tools",
        metavar="TOOL",
        help="",  # Suppress the default help to use description instead
    )

    # Add each tool as a subparser with its description
    for tool_name in sorted(TOOLS.keys()):
        description = _get_tool_description(tool_name)
        subparsers.add_parser(
            tool_name,
            help=description,
            add_help=False,  # Don't add help here, tool will handle it
        )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = build_parser()

    # If no arguments, show help
    if not argv and len(sys.argv) == 1:
        parser.print_help()
        return 1

    # Parse just the tool name first
    args, remaining = parser.parse_known_args(argv)

    # Require a tool name
    if not args.tool:
        parser.print_help()
        return 1

    # Run the specified tool with all remaining arguments
    return run_tool(args.tool, remaining)


if __name__ == "__main__":
    raise SystemExit(main())
