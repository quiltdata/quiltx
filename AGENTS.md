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

### Stack ACL (`quiltx stack acl`)

Uses the flat `policies:` / `roles:` YAML format documented in
[`spec/060-stack-acl/simpler-stack-acl.yml`](spec/060-stack-acl/simpler-stack-acl.yml).
The old `bucket_policies:` / `roles:` / `sso:` format is no longer supported.

### Config API (`quiltx.config`)

Functions for catalog configuration and credentials. Use `from quiltx.config import` for programmatic access.

## Publishing Releases

1. Update `version` in [pyproject.toml](pyproject.toml) and [CHANGELOG.md](CHANGELOG.md)
2. Merge to `main`

On each push to `main`, [.github/workflows/publish.yml](.github/workflows/publish.yml)
checks whether a `v$VERSION` tag already exists. If not, it builds, tags, creates the
GitHub release, and publishes to PyPI. If the tag already exists, the run is a no-op —
so only version bumps trigger a release.

`./poe tag` remains available for manual/local tagging if ever needed.
