"""Tests for the catalog tool (quiltx stack catalog)."""

from __future__ import annotations

from pathlib import Path

import quilt3.util as util

from quiltx.tools.stack import catalog


def test_catalog_show_displays_config(capsys) -> None:
    """Test that catalog without args displays the current config."""
    result = catalog.main([])
    # Should succeed since quilt3 has default config
    assert result == 0

    captured = capsys.readouterr()
    # Should show some config key (quilt3 has defaults)
    assert "navigator_url" in captured.out or "registry" in captured.out


def test_catalog_sets_catalog() -> None:
    """Test that catalog tool configures the catalog."""
    config_path = Path(util.CONFIG_PATH)
    backup = config_path.read_bytes() if config_path.exists() else None

    try:
        result = catalog.main([util.OPEN_DATA_URL])
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


def test_catalog_show_after_set(capsys) -> None:
    """Test that catalog without args displays the configured catalog."""
    config_path = Path(util.CONFIG_PATH)
    backup = config_path.read_bytes() if config_path.exists() else None

    try:
        # First configure
        catalog.main([util.OPEN_DATA_URL])

        # Then show
        result = catalog.main([])
        assert result == 0

        captured = capsys.readouterr()
        assert util.OPEN_DATA_URL in captured.out
    finally:
        if backup is None:
            if config_path.exists():
                config_path.unlink()
        else:
            config_path.write_bytes(backup)


def test_catalog_without_args_shows_current(capsys) -> None:
    """Test that catalog without args shows current configuration."""
    result = catalog.main([])
    # Should succeed since quilt3 has default config
    assert result == 0

    captured = capsys.readouterr()
    # Should show some config key (quilt3 has defaults)
    assert "navigator_url" in captured.out or "registry" in captured.out
