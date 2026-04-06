# quiltx

[![PyPI](https://img.shields.io/pypi/v/quiltx)](https://pypi.org/project/quiltx/)

Quilt extension toolkit for working with [Quilt](https://quiltdata.com) catalogs.

## Usage

```bash
# See available tools
uvx quiltx

# Configure a Quilt catalog
uvx quiltx config https://open.quiltdata.com

# Register a cross-account S3 bucket
uvx quiltx bucket add s3://my-data-bucket

# Discover the Quilt CloudFormation stack
uvx quiltx stack

# Tail CloudWatch logs
uvx quiltx logs --minutes 30 --filter "ERROR"

# Get help for a specific tool
uvx quiltx <tool> --help
```

## Tools

- **bucket** — Register S3 buckets with Quilt (policy, SNS, notifications)
- **config** — Configure and display Quilt catalog settings
- **stack** — Discover the Quilt CloudFormation stack and cache metadata
- **logs** — Display and tail CloudWatch logs for the configured catalog

## Python API

```python
from quiltx import get_catalog_url, get_catalog_region
from quiltx.stack import find_matching_stack

# Get catalog configuration
print(get_catalog_url())    # https://open.quiltdata.com
print(get_catalog_region()) # us-east-1

# Discover stack
stack = find_matching_stack(get_catalog_url())
print(stack["StackName"])
```

## Persistent install (optional)

```bash
uv tool install -U quiltx
# Now use without the uvx prefix:
quiltx --list
```

## License

MIT
