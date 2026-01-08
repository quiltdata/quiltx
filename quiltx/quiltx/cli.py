"""CLI for managing quiltx tools."""

from __future__ import annotations

import argparse
import importlib.metadata
import shutil
import subprocess
import sys
from typing import Iterable


def _normalize_tool_name(name: str) -> str:
    if name.startswith("quiltx-"):
        return name
    return f"quiltx-{name}"


def _iter_installed_tools() -> Iterable[str]:
    for dist in importlib.metadata.distributions():
        dist_name = dist.metadata.get("Name")
        if not dist_name:
            continue
        normalized = dist_name.lower()
        if normalized.startswith("quiltx-"):
            yield dist_name


def _list_tools() -> int:
    tools = sorted(set(_iter_installed_tools()), key=str.lower)
    if not tools:
        print("No quiltx tools installed.")
        return 0
    for tool in tools:
        print(tool)
    return 0


def _install_tools(names: list[str]) -> int:
    uv_path = shutil.which("uv")
    if not uv_path:
        print("uv is required to install tools.", file=sys.stderr)
        return 1

    exit_code = 0
    for name in names:
        tool = _normalize_tool_name(name)
        result = subprocess.run([uv_path, "tool", "install", tool], check=False)
        if result.returncode != 0:
            exit_code = result.returncode
    return exit_code


def _run_tool(name: str, args: list[str]) -> int:
    tool = _normalize_tool_name(name)

    uvx_path = shutil.which("uvx")
    if uvx_path:
        result = subprocess.run([uvx_path, tool, *args], check=False)
        return result.returncode

    tool_path = shutil.which(tool)
    if tool_path:
        result = subprocess.run([tool_path, *args], check=False)
        return result.returncode

    print(
        f"Tool '{tool}' not found. Install it with: quiltx install {tool}",
        file=sys.stderr,
    )
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage quiltx tools.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List installed quiltx tools")

    install_parser = subparsers.add_parser("install", help="Install quiltx tools")
    install_parser.add_argument("tools", nargs="+", help="Tool names to install")

    run_parser = subparsers.add_parser("run", help="Run a quiltx tool")
    run_parser.add_argument("tool", help="Tool name to run")
    run_parser.add_argument("args", nargs=argparse.REMAINDER)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        return _list_tools()
    if args.command == "install":
        return _install_tools(args.tools)
    if args.command == "run":
        return _run_tool(args.tool, args.args)

    parser.error(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
