# quiltx developer notes

## Developer

- Install dev deps: `uv sync --extra dev`
- Run tests: `./poe test`

## Publish to PyPI

The publish workflow uses GitHub OIDC trusted publishing (no API token in secrets).

1. Create or verify the project on PyPI for each package:
   - `quiltx`
   - `quiltx-log`
   - `quiltx-stack`
2. In PyPI, open each project and add a Trusted Publisher:
   - Provider: GitHub
   - Repository: `quiltdata/quiltx`
   - Workflow file: `.github/workflows/publish.yml`
   - Environment: leave blank (unless you add one in GitHub Actions)
3. Create a GitHub Release to trigger the publish workflow, or run it manually
   from the Actions tab.
