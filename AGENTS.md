# quiltx developer notes

## Developer

- Install dev deps: `uv sync --extra dev`
- Run tests: `./poe test` (unit/default) or `./poe test-all` (includes integration)
- Install git hooks: `pre-commit install && pre-commit install --hook-type pre-push`
- Run quiltx from the repo: `uv run quiltx` (or `uv run quiltx --help` to see available commands)
- Run quiltx tools via poe: `./poe run <tool>` (e.g., `./poe run config` to show current catalog)

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
