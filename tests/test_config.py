"""Tests for the config tool."""

from __future__ import annotations

from pathlib import Path

import quilt3.util as util

from quiltx.tools import config


def test_config_show_displays_config(capsys) -> None:
    """Test that config without args displays the current config."""
    result = config.main([])
    # Should succeed since quilt3 has default config
    assert result == 0

    captured = capsys.readouterr()
    # Should show some config key (quilt3 has defaults)
    assert "navigator_url" in captured.out or "registry" in captured.out


def test_config_sets_catalog() -> None:
    """Test that config tool configures the catalog."""
    config_path = Path(util.CONFIG_PATH)
    backup = config_path.read_bytes() if config_path.exists() else None

    try:
        result = config.main([util.OPEN_DATA_URL])
        assert result == 0

        # Verify config was set
        import quilt3

        cfg = quilt3.config()
        assert cfg.get("navigator_url") == util.OPEN_DATA_URL
    finally:
        if backup is None:
            if config_path.exists():
                config_path.unlink()
        else:
            config_path.write_bytes(backup)


def test_config_show_after_set(capsys) -> None:
    """Test that config without args displays the configured catalog."""
    config_path = Path(util.CONFIG_PATH)
    backup = config_path.read_bytes() if config_path.exists() else None

    try:
        # First configure
        config.main([util.OPEN_DATA_URL])

        # Then show
        result = config.main([])
        assert result == 0

        captured = capsys.readouterr()
        assert util.OPEN_DATA_URL in captured.out
    finally:
        if backup is None:
            if config_path.exists():
                config_path.unlink()
        else:
            config_path.write_bytes(backup)


def test_config_without_args_shows_current(capsys) -> None:
    """Test that config without args shows current configuration."""
    result = config.main([])
    # Should succeed since quilt3 has default config
    assert result == 0

    captured = capsys.readouterr()
    # Should show some config key (quilt3 has defaults)
    assert "navigator_url" in captured.out or "registry" in captured.out
