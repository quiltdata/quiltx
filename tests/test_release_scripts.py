"""scripts/bump_version.py and scripts/check_dist.py (release tooling)."""

from __future__ import annotations

import importlib.util
import io
import struct
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bump = _load("bump_version")
check = _load("check_dist")


@pytest.mark.parametrize(
    ("version", "part", "pre", "expected"),
    [
        ("0.23.1", "patch", None, "0.23.2"),
        ("0.23.1", "minor", None, "0.24.0"),
        ("0.23.1", "major", None, "1.0.0"),
        ("0.23.1", "minor", "a", "0.24.0a1"),
        ("0.23.1", "patch", "rc", "0.23.2rc1"),
        ("0.24.0a1", "pre", None, "0.24.0a2"),
        ("0.24.0a2", "pre", "b", "0.24.0b1"),
        ("0.24.0b1", "pre", "rc", "0.24.0rc1"),
        ("0.24.0rc1", "release", None, "0.24.0"),
    ],
)
def test_bump_version(version: str, part: str, pre: str | None, expected: str) -> None:
    assert bump.bump_version(version, part, pre) == expected


@pytest.mark.parametrize(
    ("version", "part", "pre"),
    [
        ("0.23.1", "pre", None),  # not a pre-release
        ("0.23.1", "release", None),  # already final
        ("0.24.0a1", "minor", None),  # ambiguous on a pre-release
        ("0.23.1", "minor", "alpha"),  # unknown kind
        ("0.23", "patch", None),  # not X.Y.Z
        ("0.23.1.dev1", "patch", None),  # dev releases are not bumped by this tool
    ],
)
def test_bump_version_rejects(version: str, part: str, pre: str | None) -> None:
    with pytest.raises(ValueError):
        bump.bump_version(version, part, pre)


VERSION = "0.24.0a1"


def _fat(*cpus: int) -> bytes:
    header = struct.pack(">II", check.FAT_MAGIC, len(cpus))
    entries = b"".join(struct.pack(">IIIII", cpu, 0, 0, 0, 0) for cpu in cpus)
    return header + entries


def _wheel(
    path: Path,
    extension: str,
    payload: bytes = b"x",
    extra=(),
    inner_version: str = VERSION,
    metadata_version: str = VERSION,
    typed: bool = True,
) -> None:
    with zipfile.ZipFile(path, "w") as wheel:
        wheel.writestr("quiltx/__init__.py", "")
        wheel.writestr("quiltx/auth/__init__.py", "")
        wheel.writestr("quiltx/_version.py", f'__version__ = "{inner_version}"\n')
        wheel.writestr(
            f"quiltx-{VERSION}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: quiltx\nVersion: {metadata_version}\n",
        )
        if typed:
            wheel.writestr("quiltx/py.typed", "")
        wheel.writestr(extension, payload)
        for name in extra:
            wheel.writestr(name, "")


def _sdist(
    path: Path, extra=(), skip=(), inner_version: str = VERSION, meta: str = VERSION
) -> None:
    root = f"quiltx-{VERSION}"
    files = {
        "pyproject.toml": "",
        "rust/Cargo.toml": "",
        "rust/Cargo.lock": "",
        "rust/src/lib.rs": "",
        "quiltx/__init__.py": "",
        "quiltx/_version.py": f'__version__ = "{inner_version}"\n',
        "PKG-INFO": f"Metadata-Version: 2.4\nName: quiltx\nVersion: {meta}\n",
        **{name: "" for name in extra},
    }
    with tarfile.open(path, "w:gz") as tar:
        for name, text in files.items():
            if name in skip:
                continue
            data = text.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def make_dist(directory: Path) -> None:
    prefix = f"quiltx-{VERSION}-cp310-abi3-"
    both = _fat(check.CPU_ARM64, check.CPU_X86_64)
    _wheel(
        directory / f"{prefix}manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
        "quiltx/_core.abi3.so",
    )
    _wheel(
        directory / f"{prefix}manylinux2014_aarch64.manylinux_2_17_aarch64.whl",
        "quiltx/_core.abi3.so",
    )
    for arch in ("x86_64", "aarch64"):
        _wheel(directory / f"{prefix}musllinux_1_2_{arch}.whl", "quiltx/_core.abi3.so")
    _wheel(
        directory
        / f"{prefix}macosx_10_12_universal2.macosx_10_12_x86_64.macosx_11_0_arm64.whl",
        "quiltx/_core.abi3.so",
        both,
    )
    _wheel(directory / f"{prefix}win_amd64.whl", "quiltx/_core.pyd")
    _sdist(directory / f"quiltx-{VERSION}.tar.gz")


def test_check_dist_accepts_exactly_the_seven_files(tmp_path: Path) -> None:
    make_dist(tmp_path)
    assert check.check_dist(tmp_path, VERSION) == []


def test_check_dist_flags_a_missing_wheel(tmp_path: Path) -> None:
    make_dist(tmp_path)
    next(tmp_path.glob("*win_amd64.whl")).unlink()
    problems = check.check_dist(tmp_path, VERSION)
    assert problems == ["expected exactly one windows x86_64 file, found none"]


def test_check_dist_flags_an_extra_file(tmp_path: Path) -> None:
    make_dist(tmp_path)
    name = f"quiltx-{VERSION}-cp310-abi3-win_arm64.whl"
    _wheel(tmp_path / name, "quiltx/_core.pyd")
    assert check.check_dist(tmp_path, VERSION) == [f"unexpected file: {name}"]


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_check_dist_flags_a_missing_musllinux_wheel(tmp_path: Path, arch: str) -> None:
    make_dist(tmp_path)
    next(tmp_path.glob(f"*musllinux_1_2_{arch}.whl")).unlink()
    problems = check.check_dist(tmp_path, VERSION)
    assert problems == [
        f"expected exactly one linux {arch} (musllinux_1_2) file, found none"
    ]


@pytest.mark.parametrize(
    "wrong",
    [
        "musllinux_1_1_x86_64",  # older musl baseline than promised
        "musllinux_1_2_x86_64.manylinux_2_17_x86_64",  # a mislabelled glibc build
    ],
)
def test_check_dist_flags_a_wrong_musllinux_tag(tmp_path: Path, wrong: str) -> None:
    make_dist(tmp_path)
    next(tmp_path.glob("*musllinux_1_2_x86_64.whl")).unlink()
    name = f"quiltx-{VERSION}-cp310-abi3-{wrong}.whl"
    _wheel(tmp_path / name, "quiltx/_core.abi3.so")
    problems = check.check_dist(tmp_path, VERSION)
    assert (
        "expected exactly one linux x86_64 (musllinux_1_2) file, found none" in problems
    )
    assert f"unexpected file: {name}" in problems


def test_check_dist_flags_a_thin_macos_wheel(tmp_path: Path) -> None:
    make_dist(tmp_path)
    path = next(tmp_path.glob("*universal2*.whl"))
    _wheel(path, "quiltx/_core.abi3.so", _fat(check.CPU_ARM64))
    (problem,) = check.check_dist(tmp_path, VERSION)
    assert "not a universal2 binary" in problem


def test_check_dist_flags_bundled_bytecode(tmp_path: Path) -> None:
    make_dist(tmp_path)
    path = next(tmp_path.glob("*manylinux2014_x86_64*.whl"))
    _wheel(path, "quiltx/_core.abi3.so", extra=["quiltx/__pycache__/a.cpython-312.pyc"])
    (problem,) = check.check_dist(tmp_path, VERSION)
    assert "contains bytecode" in problem


def test_check_dist_flags_a_missing_extension_and_a_rustless_sdist(
    tmp_path: Path,
) -> None:
    make_dist(tmp_path)
    path = next(tmp_path.glob("*win_amd64.whl"))
    _wheel(path, "quiltx/other.txt")
    _sdist(tmp_path / f"quiltx-{VERSION}.tar.gz", skip=["rust/src/lib.rs"])
    problems = check.check_dist(tmp_path, VERSION)
    assert any("missing compiled extension quiltx/_core.pyd" in p for p in problems)
    assert any("missing rust/src/lib.rs" in p for p in problems)


def test_check_dist_flags_the_wrong_version(tmp_path: Path) -> None:
    make_dist(tmp_path)
    problems = check.check_dist(tmp_path, "0.24.0")
    assert len([p for p in problems if p.startswith("expected exactly one")]) == 7
    assert len([p for p in problems if p.startswith("unexpected file")]) == 7


def test_check_dist_flags_a_version_that_disagrees_inside_the_files(
    tmp_path: Path,
) -> None:
    make_dist(tmp_path)
    wheel = next(tmp_path.glob("*win_amd64.whl"))
    _wheel(wheel, "quiltx/_core.pyd", inner_version="0.23.1")
    _sdist(tmp_path / f"quiltx-{VERSION}.tar.gz", meta="0.23.1")
    problems = check.check_dist(tmp_path, VERSION)
    assert any("_version.py says 0.23.1" in p for p in problems)
    assert any("metadata Version is 0.23.1" in p for p in problems)


def test_check_dist_flags_a_wheel_without_py_typed(tmp_path: Path) -> None:
    make_dist(tmp_path)
    wheel = next(tmp_path.glob("*win_amd64.whl"))
    _wheel(wheel, "quiltx/_core.pyd", typed=False)
    assert check.check_dist(tmp_path, VERSION) == [
        f"{wheel.name}: missing quiltx/py.typed"
    ]


def test_repo_version_must_match_pyproject(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "quiltx").mkdir()
    (tmp_path / "quiltx" / "_version.py").write_text('__version__ = "0.23.1"\n')
    monkeypatch.chdir(tmp_path)
    assert check.repo_version_problems("0.23.1") == []
    (problem,) = check.repo_version_problems("0.24.0a1")
    assert "says 0.23.1" in problem and "pyproject.toml says 0.24.0a1" in problem


def test_this_repo_versions_agree() -> None:
    path = ROOT / "quiltx" / "_version.py"
    if not path.exists():  # CI runs the suite from a copy without the source package
        pytest.skip("no quiltx/ source tree next to the tests")
    version = check.project_version()
    found = check.VERSION_ASSIGNMENT.search(path.read_text())
    assert found and found.group(1) == version
