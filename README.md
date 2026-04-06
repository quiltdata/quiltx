# quiltx

[![PyPI](https://img.shields.io/pypi/v/quiltx)](https://pypi.org/project/quiltx/)

Quilt extension toolkit for working with [Quilt](https://quiltdata.com) catalogs.

## Install

```bash
uvx quiltx --list
```

## Usage

```bash
# List available tools
quiltx --list

# Configure a Quilt catalog
quiltx config https://open.quiltdata.com

# Register a cross-account S3 bucket
quiltx bucket add s3://my-data-bucket

# Discover the Quilt CloudFormation stack
quiltx stack

# Tail CloudWatch logs
quiltx logs --minutes 30 --filter "ERROR"

# Get help
quiltx --help
quiltx <tool> --help
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

## License

MIT
