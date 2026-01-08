from __future__ import annotations

from pathlib import Path

import quilt3
import quilt3.util as util

import quiltx


def test_configured_catalog_sets_open_quiltdata() -> None:
    config_path = Path(util.CONFIG_PATH)
    backup = config_path.read_bytes() if config_path.exists() else None

    try:
        config = quiltx.configured_catalog(util.OPEN_DATA_URL)

        assert config.get("navigator_url") == util.OPEN_DATA_URL
    finally:
        if backup is None:
            if config_path.exists():
                config_path.unlink()
        else:
            config_path.write_bytes(backup)
