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


VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")
PRE_KINDS = ("a", "b", "rc")


def bump_version(version: str, part: str, pre: str | None = None) -> str:
    """Return the next version.

    *part* is ``major``, ``minor`` or ``patch`` (bump the release segment),
    ``pre`` (next pre-release number: 0.24.0a1 -> 0.24.0a2) or ``release``
    (drop the pre-release segment: 0.24.0a2 -> 0.24.0). *pre* (``a``, ``b`` or
    ``rc``) makes a major/minor/patch bump a first pre-release: 0.23.1 -> 0.24.0a1.
    Versions follow PEP 440, so pip does not install a pre-release by default.
    """
    match = VERSION_RE.match(version)
    if not match:
        raise ValueError(f"Unsupported version format: {version}")
    major, minor, patch = (int(piece) for piece in match.groups()[:3])
    current_kind, current_number = match.group(4), match.group(5)
    if pre is not None and pre not in PRE_KINDS:
        raise ValueError(f"Unknown pre-release kind: {pre}")

    if part == "pre":
        if current_kind is None:
            raise ValueError(
                f"{version} is not a pre-release; "
                "use major/minor/patch with --pre to start one"
            )
        kind = pre or current_kind
        number = int(current_number) + 1 if kind == current_kind else 1
        return f"{major}.{minor}.{patch}{kind}{number}"
    if part == "release":
        if current_kind is None:
            raise ValueError(f"{version} is already a final release")
        return f"{major}.{minor}.{patch}"
    if current_kind is not None:
        raise ValueError(
            f"{version} is a pre-release; use `pre` for the next one "
            "or `release` for the final version"
        )
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
    return f"{major}.{minor}.{patch}" + (f"{pre}1" if pre else "")


def update_file(path: Path, pattern: str, repl: str) -> None:
    content = path.read_text()
    updated, count = re.subn(pattern, repl, content, count=1, flags=re.MULTILINE)
    if count == 0:
        raise ValueError(f"Pattern not found in {path}")
    path.write_text(updated)


def main() -> int:
    args = sys.argv[1:]
    pre = None
    if "--pre" in args:
        index = args.index("--pre")
        try:
            pre = args[index + 1]
        except IndexError:
            print("Error: --pre needs a kind: a, b or rc")
            return 2
        del args[index : index + 2]
    part = args[0] if args else "patch"

    # Check for uncommitted changes
    check_git_status()

    pyproject = Path("pyproject.toml")
    version_file = Path("quiltx/_version.py")

    match = re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.MULTILINE)
    if not match:
        raise ValueError("version not found in pyproject.toml")

    current_version = match.group(1)
    try:
        next_version = bump_version(current_version, part, pre)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    print(f"Bumping version: {current_version} -> {next_version}")

    # Update version in files
    update_file(pyproject, r'^version = "[^"]+"', f'version = "{next_version}"')
    update_file(
        version_file, r'^__version__ = "[^"]+"', f'__version__ = "{next_version}"'
    )

    # Update uv.lock
    print("Updating uv.lock...")
    run_command(["uv", "lock"])

    # Commit all changes
    print("Committing changes...")
    run_command(["git", "add", "pyproject.toml", "quiltx/_version.py", "uv.lock"])
    run_command(["git", "commit", "-m", f"Bump version to {next_version}"])

    print(f"✓ Version bumped to {next_version} and committed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
