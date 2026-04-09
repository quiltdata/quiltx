# quiltx

[![PyPI](https://img.shields.io/pypi/v/quiltx)](https://pypi.org/project/quiltx/)

Quilt extension toolkit for working with [Quilt](https://quiltdata.com) catalogs.

## Usage

```bash
# See available tools
uvx quiltx

# Configure a Quilt catalog
uvx quiltx stack catalog https://open.quiltdata.com

# Register a cross-account S3 bucket
uvx quiltx bucket add s3://my-data-bucket

# Discover the Quilt CloudFormation stack
uvx quiltx stack cfn

# Open an interactive shell in a running ECS task
uvx quiltx ecs

# Tail CloudWatch logs
uvx quiltx logs --minutes 30 --filter "ERROR"

# Get help for a specific tool
uvx quiltx <tool> --help
```

## Tools

- **bucket** — Register S3 buckets with Quilt (policy, SNS, notifications)
- **ecs** — Interactive shell access to running ECS tasks via Session Manager
- **logs** — Display and tail CloudWatch logs for the configured catalog
- **stack** — Manage Quilt stack
  - **stack catalog** — Configure and display Quilt catalog settings
  - **stack cfn** — Discover the Quilt CloudFormation stack and cache metadata

## Python API

```python
from quiltx import get_catalog_url, get_catalog_region, get_catalog_config, set_catalog_url
from quiltx.stack import find_matching_stack

# Configure a catalog
set_catalog_url("https://open.quiltdata.com")

# Read catalog configuration
print(get_catalog_url())    # https://open.quiltdata.com
print(get_catalog_region()) # us-east-1
print(get_catalog_config()) # full config dict

# Discover stack
stack = find_matching_stack(get_catalog_url())
print(stack["StackName"])

# Register an S3 bucket (policy, SNS, notifications, catalog)
from quiltx.bucket import add_bucket

result = add_bucket("my-data-bucket", title="My Data")
print(result.sns_topic_arn)
print(result.already_registered)
```

## Persistent install (optional)

```bash
uv tool install -U quiltx
# Now use without the uvx prefix:
quiltx --list
```

## License

MIT
