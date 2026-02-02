# quiltx developer notes

## Developer Setup

- Setup: `./poe setup` (install deps + hooks)
- Run tests: `./poe test` (unit) or `./poe test-all` (full suite)
- Run from repo: `./poe run <tool>` (e.g., `./poe run config --help`)

## Tools

### ECS Tool (`quiltx ecs`)

Opens interactive shell in running ECS tasks. Requires AWS Session Manager plugin (CLI will prompt with install instructions).

### Stack API (`quiltx.stack`)

Python module for discovering CloudFormation stacks and working with cached stack data. See module docstrings for API details.

### Config API (`quiltx.config`)

Functions for catalog configuration and credentials. Use `from quiltx.config import` for programmatic access.

## Publishing Releases

1. Update `version` in [pyproject.toml](pyproject.toml) and [CHANGELOG.md](CHANGELOG.md)
2. Run `./poe tag` to create and push git tag
3. GitHub workflow auto-creates release and publishes to PyPI after approval

See [.github/workflows/publish.yml](.github/workflows/publish.yml) for workflow details.
