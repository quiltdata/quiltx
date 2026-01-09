from __future__ import annotations

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from quiltx import stack


def main() -> int:
    import quilt3

    config = quilt3.config()
    catalog_url = config.get("navigator_url")
    if not catalog_url:
        raise SystemExit("navigator_url not configured")

    catalog_name = stack.extract_catalog_name(config)
    catalog_config = stack.fetch_catalog_config(str(catalog_url))
    region = stack.resolve_region(config, catalog_config)

    print(f"catalog_url={catalog_url}")
    print(f"catalog_name={catalog_name}")
    print(f"region={region}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
