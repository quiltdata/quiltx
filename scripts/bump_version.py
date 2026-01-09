#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def check_git_status() -> None:
    """Ensure there are no uncommitted changes."""
    result = run_command(["git", "status", "--porcelain"])
    if result.stdout.strip():
        print("Error: You have uncommitted changes. Please commit or stash them first.")
        print(result.stdout)
        sys.exit(1)


def bump_version(version: str, part: str) -> str:
    parts = version.split(".")
    if len(parts) != 3 or not all(piece.isdigit() for piece in parts):
        raise ValueError(f"Unsupported version format: {version}")

    major, minor, patch = (int(piece) for piece in parts)
    if part == "major":
        major += 1
        minor = 0
        patch = 0
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "patch":
        patch += 1
    else:
        raise ValueError(f"Unknown bump part: {part}")
    return f"{major}.{minor}.{patch}"


def update_file(path: Path, pattern: str, repl: str) -> None:
    content = path.read_text()
    updated, count = re.subn(pattern, repl, content, count=1, flags=re.MULTILINE)
    if count == 0:
        raise ValueError(f"Pattern not found in {path}")
    path.write_text(updated)


def main() -> int:
    part = sys.argv[1] if len(sys.argv) > 1 else "patch"

    # Check for uncommitted changes
    check_git_status()

    pyproject = Path("pyproject.toml")
    init_file = Path("quiltx/__init__.py")

    match = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.MULTILINE)
    if not match:
        raise ValueError("version not found in pyproject.toml")

    current_version = match.group(1)
    next_version = bump_version(current_version, part)

    print(f"Bumping version: {current_version} -> {next_version}")

    # Update version in files
    update_file(pyproject, r'^version = "[^"]+"', f'version = "{next_version}"')
    update_file(init_file, r'^__version__ = "[^"]+"', f'__version__ = "{next_version}"')

    # Update uv.lock
    print("Updating uv.lock...")
    run_command(["uv", "lock"])

    # Commit all changes
    print("Committing changes...")
    run_command(["git", "add", "pyproject.toml", "quiltx/__init__.py", "uv.lock"])
    run_command(["git", "commit", "-m", f"Bump version to {next_version}"])

    print(f"✓ Version bumped to {next_version} and committed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
