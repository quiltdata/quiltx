"""Tests for the unified quiltx CLI."""

from __future__ import annotations

import quiltx.cli as cli


def test_list_tools(capsys) -> None:
    """Test that list_tools shows all available tools."""
    cli.list_tools()
    captured = capsys.readouterr()

    # Should list all registered tools
    assert "log" in captured.out
    assert "stack" in captured.out


def test_run_tool_unknown(capsys) -> None:
    """Test running an unknown tool fails gracefully."""
    result = cli.run_tool("nonexistent", [])
    assert result == 1

    captured = capsys.readouterr()
    assert "Unknown tool 'nonexistent'" in captured.err


def test_main_no_args(capsys) -> None:
    """Test main with no arguments shows help."""
    result = cli.main([])
    assert result == 1

    captured = capsys.readouterr()
    assert "quiltx" in captured.out


def test_main_list_flag(capsys) -> None:
    """Test main with --list flag."""
    result = cli.main(["--list"])
    assert result == 0

    captured = capsys.readouterr()
    assert "log" in captured.out
    assert "stack" in captured.out


def test_run_tool_log() -> None:
    """Test that log tool can be invoked."""
    result = cli.run_tool("log", ["test message"])
    assert result == 0


def test_run_tool_stack() -> None:
    """Test that stack tool can be invoked."""
    result = cli.run_tool("stack", ["--limit", "1"])
    assert result == 0
