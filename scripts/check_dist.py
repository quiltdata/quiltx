#!/usr/bin/env python3
"""Check that a directory holds exactly the quiltx release artifacts.

A release is five files and no others:

* ``quiltx-<v>.tar.gz`` (sdist)
* ``quiltx-<v>-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl``
* ``quiltx-<v>-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl``
* ``quiltx-<v>-cp310-abi3-macosx_*_universal2.whl`` (arm64 + x86_64 in one file)
* ``quiltx-<v>-cp310-abi3-win_amd64.whl``

Beyond the file names it checks what is inside: the compiled extension is
present (and, for macOS, contains both architectures), no bytecode was bundled,
the sdist carries the Rust sources so ``pip install`` can build from source, and
every file is PyPI-uploadable. PyPI never lets a filename be reused, so this runs
before anything is uploaded.

Usage:
    python scripts/check_dist.py DIST_DIR [VERSION]   # VERSION defaults to pyproject.toml
"""

from __future__ import annotations

import re
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

# Mach-O fat (universal) binary header, big-endian, and its CPU types.
FAT_MAGIC = 0xCAFEBABE
CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C


def expected_patterns(version: str) -> dict[str, str]:
    """Label -> regex that exactly one file name in the directory must match."""
    v = re.escape(version)
    return {
        "sdist": rf"quiltx-{v}\.tar\.gz",
        "linux x86_64 (manylinux2014)": (
            rf"quiltx-{v}-cp310-abi3-"
            r"manylinux_2_17_x86_64\.manylinux2014_x86_64\.whl"
        ),
        "linux aarch64 (manylinux2014)": (
            rf"quiltx-{v}-cp310-abi3-"
            r"manylinux_2_17_aarch64\.manylinux2014_aarch64\.whl"
        ),
        "macOS universal2": rf"quiltx-{v}-cp310-abi3-macosx_\d+_\d+_universal2\.whl",
        "windows x86_64": rf"quiltx-{v}-cp310-abi3-win_amd64\.whl",
    }


def fat_architectures(data: bytes) -> set[int]:
    """CPU types listed in a Mach-O fat header; empty if *data* is not fat."""
    if len(data) < 8:
        return set()
    magic, count = struct.unpack(">II", data[:8])
    if magic != FAT_MAGIC or not 0 < count < 32:
        return set()
    cpus = set()
    for index in range(count):
        offset = 8 + index * 20
        cpus.add(struct.unpack(">I", data[offset : offset + 4])[0])
    return cpus


def _bytecode(names: list[str]) -> list[str]:
    return [n for n in names if "__pycache__" in n or n.endswith((".pyc", ".pyo"))]


def check_wheel(path: Path, label: str) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        extension = (
            "quiltx/_core.pyd" if label == "windows x86_64" else "quiltx/_core.abi3.so"
        )
        if extension not in names:
            problems.append(f"{path.name}: missing compiled extension {extension}")
        elif label == "macOS universal2":
            archs = fat_architectures(wheel.read(extension))
            if archs != {CPU_X86_64, CPU_ARM64}:
                problems.append(
                    f"{path.name}: {extension} is not a universal2 binary "
                    f"(cpu types {sorted(hex(a) for a in archs) or 'none'})"
                )
        for required in ("quiltx/__init__.py", "quiltx/auth/__init__.py"):
            if required not in names:
                problems.append(f"{path.name}: missing {required}")
        if _bytecode(names):
            problems.append(f"{path.name}: contains bytecode: {_bytecode(names)[:3]}")
    return problems


def check_sdist(path: Path, version: str) -> list[str]:
    problems: list[str] = []
    with tarfile.open(path) as sdist:
        names = sdist.getnames()
    root = f"quiltx-{version}"
    for required in (
        "pyproject.toml",
        "rust/Cargo.toml",
        "rust/Cargo.lock",
        "rust/src/lib.rs",
        "quiltx/__init__.py",
    ):
        if f"{root}/{required}" not in names:
            problems.append(f"{path.name}: missing {required}")
    if _bytecode(names):
        problems.append(f"{path.name}: contains bytecode: {_bytecode(names)[:3]}")
    return problems


def check_dist(dist_dir: Path, version: str) -> list[str]:
    """Return every problem found; an empty list means the set is exactly right."""
    problems: list[str] = []
    files = sorted(p for p in dist_dir.iterdir() if p.is_file())
    unclaimed = {p.name for p in files}
    for label, pattern in expected_patterns(version).items():
        matches = [p for p in files if re.fullmatch(pattern, p.name)]
        if len(matches) != 1:
            found = [m.name for m in matches] or "none"
            problems.append(f"expected exactly one {label} file, found {found}")
            continue
        unclaimed.discard(matches[0].name)
        if label == "sdist":
            problems += check_sdist(matches[0], version)
        else:
            problems += check_wheel(matches[0], label)
    for name in sorted(unclaimed):
        problems.append(f"unexpected file: {name}")
    return problems


def project_version() -> str:
    text = Path("pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("version not found in pyproject.toml")
    return match.group(1)


def main(argv: list[str]) -> int:
    if not 1 <= len(argv) <= 2:
        print(__doc__)
        return 2
    dist_dir = Path(argv[0])
    version = argv[1] if len(argv) == 2 else project_version()
    problems = check_dist(dist_dir, version)
    if problems:
        for problem in problems:
            print(f"::error::{problem}" if _in_actions() else f"error: {problem}")
        return 1
    print(f"{dist_dir}: exactly the 5 expected files for quiltx {version}")
    for path in sorted(dist_dir.iterdir()):
        print(f"  {path.name}  {path.stat().st_size:,} bytes")
    return 0


def _in_actions() -> bool:
    import os

    return os.environ.get("GITHUB_ACTIONS") == "true"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
