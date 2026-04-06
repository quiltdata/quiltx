#!/usr/bin/env python3
"""Extract release notes for a version from CHANGELOG.md.

Usage:
    python scripts/release_notes.py          # uses version from pyproject.toml
    python scripts/release_notes.py 0.4.0    # explicit version
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def get_version_from_pyproject() -> str:
    text = Path("pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("version not found in pyproject.toml")
    return match.group(1)


def extract_changelog(version: str) -> str:
    text = Path("CHANGELOG.md").read_text()
    # Match "## [version]" header and capture everything until the next "## [" header
    pattern = rf"## \[{re.escape(version)}\][^\n]*\n(.*?)(?=\n## \[|\Z)"
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        return f"Release {version}"
    return match.group(1).strip()


def build_release_notes(version: str) -> str:
    changelog = extract_changelog(version)
    return f"""\
[![PyPI](https://img.shields.io/pypi/v/quiltx)](https://pypi.org/project/quiltx/{version}/)

A new release of quiltx is [available](https://pypi.org/project/quiltx/{version}/). To see all available commands, run:
```bash
uvx quiltx
```

{changelog}"""


def main() -> int:
    version = sys.argv[1] if len(sys.argv) > 1 else get_version_from_pyproject()
    print(build_release_notes(version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
