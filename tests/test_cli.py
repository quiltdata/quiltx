"""Tests for the unified quiltx CLI."""

from __future__ import annotations

import pytest

import quiltx.cli as cli


def test_list_tools(capsys) -> None:
    """Test that list_tools outputs available tools."""
    cli.list_tools()
    captured = capsys.readouterr()

    # Should have header and at least one tool
    assert "Available tools:" in captured.out
    assert len(cli.TOOLS) > 0


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


def test_main_shows_tools(capsys) -> None:
    """Test that main shows available tools in help."""
    result = cli.main([])
    assert result == 1  # Returns 1 because no tool specified

    captured = capsys.readouterr()
    assert "available tools:" in captured.out
    # Check that at least one tool is shown
    assert any(tool in captured.out for tool in cli.TOOLS.keys())


def test_run_tool_exists() -> None:
    """Test that we can invoke an existing tool."""
    # Get any tool from the registry
    if cli.TOOLS:
        tool_name = next(iter(cli.TOOLS))
        # --help causes SystemExit(0), which is expected
        with pytest.raises(SystemExit) as exc_info:
            cli.run_tool(tool_name, ["--help"])
        assert exc_info.value.code == 0
