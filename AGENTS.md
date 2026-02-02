# quiltx developer notes

## Developer

- Setup (install deps + hooks): `./poe setup`
- Run tests: `./poe test` (unit) or `./poe test-all` (full suite with linting)
- Run quiltx from the repo: `./poe run <tool>` (e.g., `./poe run config` or `./poe run --help`)

## ECS Tool

The `quiltx ecs` tool opens an interactive shell in running ECS tasks.

### Prerequisites

Requires AWS Session Manager plugin. If the plugin is not installed, `./poe run ecs` will display installation instructions with platform-specific commands.

**Installation:**
- **macOS/Linux/Windows**: Run `./poe run ecs` and follow the instructions, or see the [official AWS documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html).

### Usage

```bash
# List available ECS clusters and services
./poe run ecs --list

# Open shell in a specific service
./poe run ecs RegistryService

# Check network connectivity from ECS to catalog services
./poe run ecs --reachability
```

## Stack API

The `quiltx.stack` module provides functions for discovering and working with CloudFormation stacks.

### Simplified API

Stack discovery functions automatically handle AWS client creation and region detection:

```python
from quiltx.stack import find_matching_stack, list_log_group_resources, list_ecs_resources

# Simplest usage - auto-detects region from catalog config
stack = find_matching_stack("https://example.quiltdata.com")

# Explicit region
stack = find_matching_stack("https://example.quiltdata.com", region="us-east-1")

# Advanced: provide your own boto3 client
import boto3
cfn_client = boto3.client("cloudformation", region_name="us-east-1")
stack = find_matching_stack("https://example.quiltdata.com", cfn_client=cfn_client)

# List resources
log_groups = list_log_group_resources(stack["StackName"], region="us-east-1")
ecs_resources = list_ecs_resources(stack["StackName"], region="us-east-1")
```

### Loading Cached Stack Data

For most use cases, use the cached stack payload instead of querying AWS:

```python
from quiltx.stack import load_stack_payload

# Returns cached data from ~/.local/share/quiltx/{catalog_name}/stack.json
payload = load_stack_payload("example.quiltdata.com")
if payload:
    print(f"Region: {payload['region']}")
    print(f"Stack: {payload['stack_name']}")
```

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

3. **Automated Release and Publishing**:

   The tag push automatically triggers the [publish workflow](.github/workflows/publish.yml) which:
   - Builds the package with uv
   - **Automatically creates a GitHub Release** with auto-generated release notes from commits
   - Attaches distribution files (wheel and tarball) to the release
   - Waits for approval from a designated reviewer
   - Publishes to PyPI using OIDC trusted publishing

   The release notes are auto-generated from commit messages. To view or edit the release:
   - Go to the repository's Releases page (https://github.com/quiltdata/quiltx/releases)
   - Find the newly created release for your tag
   - Optionally edit to add custom release notes from [CHANGELOG.md](CHANGELOG.md)

   You can also trigger the publish workflow manually from the Actions tab if needed.
