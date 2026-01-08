# quiltx developer notes

## Developer

- Install dev deps: `uv sync --extra dev`
- Run tests: `./poe test`
- Run quiltx from the repo: `uv run quiltx` (or `uv run quiltx --help` to see available commands)
- Run quiltx tools via poe: `./poe run <tool>` (e.g., `./poe run config` to show current catalog)

## Publish to PyPI

The publish workflow uses GitHub OIDC trusted publishing (no API token in secrets) and requires approval via a GitHub environment.

### Initial Setup

1. **Configure GitHub Environment** (one-time setup):
   - Go to repository Settings > Environments
   - Create environment named `pypi`
   - Configure protection rules:
     - Required reviewers: Add maintainers who can approve deployments
     - Deployment branches: Select "Selected branches" and add `main`
   - Save the environment

2. **Create or verify the project on PyPI**:
   - `quiltx`

3. **In PyPI, open each project and add a Trusted Publisher**:
   - Provider: GitHub
   - Repository: `quiltdata/quiltx`
   - Workflow file: `.github/workflows/publish.yml`
   - Environment name: `pypi` (must match the GitHub environment)

### Publishing a Release

1. Create a GitHub Release to trigger the publish workflow, or run it manually
   from the Actions tab.
2. The workflow will wait for approval from a designated reviewer.
3. Once approved, packages will be published to PyPI.
