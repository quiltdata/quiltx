# quiltx developer notes

## Developer

- Setup (install deps + hooks): `./poe setup`
- Run tests: `./poe test` (unit) or `./poe test-all` (full suite with linting)
- Run quiltx from the repo: `./poe run <tool>` (e.g., `./poe run config` or `./poe run --help`)

## Stack Payload Version Checking

The `stack.json` file includes a `quiltx_version` field that records which version of quiltx created it. Tools can use `ensure_min_version()` to check if the stack payload is compatible with features they need.

### Usage Example

```python
from quiltx.stack import load_stack_payload, ensure_min_version

def main(argv: list[str] | None = None) -> int:
    catalog_name = "example.quiltdata.com"
    payload = load_stack_payload(catalog_name)

    # Check if payload has features added in 0.1.3
    if not ensure_min_version(payload, "0.1.3"):
        print("Stack data outdated. Run 'quiltx stack' to refresh.", file=sys.stderr)
        return 1

    # Use payload data...
    return 0
```

### When to Require a Minimum Version

Only require a minimum version when:

- A new field was added to `stack.json` that your tool depends on
- The structure of existing data changed in a breaking way

Example: If version 0.1.2 added `ecs_resources` to the payload, a tool that needs ECS resources should check for `"0.1.2"`.

### Version Field in stack.json

The version is automatically included when `write_stack_payload()` is called:

```json
{
  "catalog_name": "example.quiltdata.com",
  "quiltx_version": "0.1.3",
  ...
}
```

## Publish to PyPI

The publish workflow uses GitHub OIDC trusted publishing (no API token in secrets) and requires approval via a GitHub environment.

### Publishing a Release

1. **Update version and changelog**:
   - Update `version` in [pyproject.toml](pyproject.toml)
   - Update [CHANGELOG.md](CHANGELOG.md) with release notes for the new version

2. **Create and push a git tag**:

   ```bash
   ./poe tag
   ```

   This poe task will:
   - Read the version from `pyproject.toml`
   - Create an annotated tag `v{version}` (e.g., `v0.1.0`)
   - Push the tag to GitHub

   If the tag already exists, you can delete it with:

   ```bash
   git tag -d v0.1.0 && git push origin :refs/tags/v0.1.0
   ```

3. **Create a GitHub Release**:
   - Go to the repository's Releases page
   - Click "Draft a new release"
   - Select the tag you just pushed (e.g., `v0.1.0`)
   - Add release notes (can copy from CHANGELOG.md)
   - Publish the release

   This triggers the [publish workflow](.github/workflows/publish.yml) which:
   - Waits for approval from a designated reviewer
   - Builds the package
   - Publishes to PyPI using OIDC trusted publishing

Alternatively, you can trigger the publish workflow manually from the Actions tab.
