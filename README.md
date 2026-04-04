# quiltx

Quilt extension toolkit with shared utilities for working with [Quilt](https://docs.quilt.bio) catalogs.

## Installation

```bash
# No installation needed! Use uvx to run directly:
uvx quiltx --list
```

## Usage

Run tools directly with `uvx` (recommended):

```bash
# List available tools
uvx quiltx --list

# Configure a Quilt catalog
uvx quiltx config https://open.quiltdata.com

# Show current catalog configuration
uvx quiltx config

# Get help
uvx quiltx --help
uvx quiltx <tool> --help
```

Or if installed with `pipx`:

```bash
quiltx --list
quiltx config https://open.quiltdata.com
quiltx stack
quiltx logs --minutes 30 --filter "ERROR"
```

## Built-in Tools

- **bucket**: Register buckets with Quilt and configure bucket policy/SNS notifications
- **config**: Configure and display Quilt catalog settings
- **stack**: Discover the Quilt CloudFormation stack and cache log group metadata in `stack.json`
- **logs**: Display CloudWatch Logs for the configured catalog using `stack.json`

## API Examples

### Discover Stack Name

```python
from quiltx import get_catalog_url
from quiltx.stack import find_matching_stack

stack = find_matching_stack(get_catalog_url())
print(stack["StackName"])
```

### Get Catalog Configuration

```python
from quiltx import get_catalog_url, get_catalog_region

# Get specific configuration values
catalog_url = get_catalog_url()
region = get_catalog_region()

print(f"Catalog: {catalog_url}")
print(f"Region: {region}")
```

## License

MIT License - see LICENSE file for details
