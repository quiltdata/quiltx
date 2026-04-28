"""User-level quiltx configuration (default catalog, etc.).

Stores data at user_data_path("quiltx")/config.json.
Schema today: { "default_catalog": "<dns>" }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from platformdirs import user_data_path


def _config_path() -> Path:
    return user_data_path("quiltx") / "config.json"


def _read() -> dict[str, Any]:
    path = _config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _write(data: dict[str, Any]) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_default_catalog() -> str | None:
    """Return the stored default catalog DNS, or None if not set."""
    return _read().get("default_catalog") or None


def set_default_catalog(dns: str) -> None:
    """Store dns as the default catalog."""
    data = _read()
    data["default_catalog"] = dns
    _write(data)


def clear_default_catalog() -> None:
    """Remove the default_catalog key from config (leaves file intact)."""
    data = _read()
    data.pop("default_catalog", None)
    _write(data)
