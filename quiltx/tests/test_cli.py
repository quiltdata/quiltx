from __future__ import annotations

import types

import quiltx.cli as cli


def _dist(name: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(metadata={"Name": name})


def test_normalize_tool_name() -> None:
    assert cli._normalize_tool_name("quiltx-log") == "quiltx-log"
    assert cli._normalize_tool_name("log") == "quiltx-log"


def test_iter_installed_tools_filters_quiltx(monkeypatch) -> None:
    monkeypatch.setattr(
        cli.importlib.metadata,
        "distributions",
        lambda: [_dist("Quiltx-Log"), _dist("other"), _dist("quiltx-stack")],
    )

    assert list(cli._iter_installed_tools()) == ["Quiltx-Log", "quiltx-stack"]


def test_list_tools_empty(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_iter_installed_tools", lambda: [])

    assert cli._list_tools() == 0

    captured = capsys.readouterr()
    assert captured.out.strip() == "No quiltx tools installed."


def test_list_tools_sorted(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "_iter_installed_tools",
        lambda: ["quiltx-stack", "Quiltx-Log"],
    )

    assert cli._list_tools() == 0

    captured = capsys.readouterr()
    assert captured.out.strip().splitlines() == ["Quiltx-Log", "quiltx-stack"]
