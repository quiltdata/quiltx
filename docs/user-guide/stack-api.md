# Stack API Guide

The `quiltx.stack` module provides Python functions for discovering and working with CloudFormation stacks associated with Quilt deployments. This is useful for building custom tools and automation.

## Overview

The Stack API provides two main workflows:

1. **Discovery**: Find CloudFormation stacks and query their resources
2. **Caching**: Load pre-cached stack data for fast, offline access

## Quick Start

```python
from quiltx.stack import find_matching_stack, load_stack_payload

# Option 1: Discover stack (queries AWS)
stack = find_matching_stack("https://example.quiltdata.com")
print(f"Stack: {stack['StackName']}")

# Option 2: Load cached data (no AWS calls)
payload = load_stack_payload("example.quiltdata.com")
if payload:
    print(f"Stack: {payload['stack_name']}")
    print(f"Region: {payload['region']}")
```

## Discovery Functions

### find_matching_stack()

Discovers the CloudFormation stack for a Quilt catalog by querying AWS.

**Signature:**

```python
def find_matching_stack(
    catalog_url: str,
    region: str | None = None,
    cfn_client: Any | None = None
) -> dict[str, Any]:
    ...
```

**Parameters:**

- `catalog_url` - Full catalog URL (e.g., `"https://example.quiltdata.com"`)
- `region` - AWS region (optional, auto-detected from catalog config if not provided)
- `cfn_client` - Boto3 CloudFormation client (optional, created automatically if not provided)

**Returns:**

Dictionary containing stack information from CloudFormation's `describe_stacks` API.

**Examples:**

```python
from quiltx.stack import find_matching_stack

# Simplest usage - auto-detects region
stack = find_matching_stack("https://example.quiltdata.com")

# Explicit region
stack = find_matching_stack(
    "https://example.quiltdata.com",
    region="us-east-1"
)

# Provide your own boto3 client
import boto3
cfn_client = boto3.client("cloudformation", region_name="us-east-1")
stack = find_matching_stack(
    "https://example.quiltdata.com",
    cfn_client=cfn_client
)
```

**When to use:**

- Initial stack discovery
- Verifying stack exists
- Getting real-time stack status
- Building tools that need fresh stack data

### list_log_group_resources()

Lists CloudWatch log group resources from a CloudFormation stack.

**Signature:**

```python
def list_log_group_resources(
    stack_name: str,
    region: str | None = None,
    cfn_client: Any | None = None
) -> list[dict[str, Any]]:
    ...
```

**Parameters:**

- `stack_name` - CloudFormation stack name
- `region` - AWS region (optional)
- `cfn_client` - Boto3 CloudFormation client (optional)

**Returns:**

List of log group resource dictionaries with keys:
- `LogicalResourceId` - Logical ID in CloudFormation template
- `PhysicalResourceId` - Actual log group name
- `ResourceType` - Always `"AWS::Logs::LogGroup"`

**Example:**

```python
from quiltx.stack import find_matching_stack, list_log_group_resources

stack = find_matching_stack("https://example.quiltdata.com")
log_groups = list_log_group_resources(
    stack["StackName"],
    region="us-east-1"
)

for lg in log_groups:
    print(f"Log Group: {lg['PhysicalResourceId']}")
```

**When to use:**

- Building log viewing tools
- Finding available log streams
- Monitoring log group creation

### list_ecs_resources()

Lists ECS cluster and service resources from a CloudFormation stack.

**Signature:**

```python
def list_ecs_resources(
    stack_name: str,
    region: str | None = None,
    cfn_client: Any | None = None
) -> dict[str, Any]:
    ...
```

**Parameters:**

- `stack_name` - CloudFormation stack name
- `region` - AWS region (optional)
- `cfn_client` - Boto3 CloudFormation client (optional)

**Returns:**

Dictionary with keys:
- `clusters` - List of ECS cluster ARNs
- `services` - List of ECS service ARNs

**Example:**

```python
from quiltx.stack import find_matching_stack, list_ecs_resources

stack = find_matching_stack("https://example.quiltdata.com")
ecs_resources = list_ecs_resources(
    stack["StackName"],
    region="us-east-1"
)

print(f"Clusters: {ecs_resources['clusters']}")
print(f"Services: {ecs_resources['services']}")
```

**When to use:**

- Building ECS management tools
- Discovering running services
- Automating ECS operations

## Caching Functions

### load_stack_payload()

Loads cached stack data from disk. This is the **recommended way** to access stack data in most tools since it's fast and doesn't require AWS credentials.

**Signature:**

```python
def load_stack_payload(catalog_name: str) -> dict[str, Any] | None:
    ...
```

**Parameters:**

- `catalog_name` - Catalog hostname (e.g., `"example.quiltdata.com"`)

**Returns:**

Dictionary containing cached stack data, or `None` if not found.

**Payload Structure:**

```python
{
    "catalog_name": "example.quiltdata.com",
    "quiltx_version": "0.2.0",
    "region": "us-east-1",
    "stack_name": "QuiltStack-prod",
    "log_groups": [
        {
            "LogicalResourceId": "APILogGroup",
            "PhysicalResourceId": "/aws/apigateway/quilt-api",
            "ResourceType": "AWS::Logs::LogGroup"
        }
    ],
    "ecs_resources": {
        "clusters": ["arn:aws:ecs:us-east-1:123456789012:cluster/QuiltCluster"],
        "services": ["arn:aws:ecs:us-east-1:123456789012:service/QuiltService"]
    },
    "eventbridge_resources": [
        ...
    ]
}
```

**Example:**

```python
from quiltx.stack import load_stack_payload

payload = load_stack_payload("example.quiltdata.com")
if payload:
    print(f"Region: {payload['region']}")
    print(f"Stack: {payload['stack_name']}")
    print(f"Log Groups: {len(payload.get('log_groups', []))}")
else:
    print("No cached data. Run 'quiltx stack' first.")
```

**Cache Location:**

`~/.local/share/quiltx/{catalog_name}/stack.json`

**When to use:**

- In tools that need stack data
- When AWS credentials aren't available
- For fast, offline access
- Most use cases (prefer this over `find_matching_stack()`)

### write_stack_payload()

Writes stack data to the cache. Used internally by `quiltx stack`.

**Signature:**

```python
def write_stack_payload(
    catalog_name: str,
    region: str,
    stack_name: str,
    log_groups: list[dict[str, Any]],
    ecs_resources: dict[str, Any],
    eventbridge_resources: list[dict[str, Any]] | None = None
) -> None:
    ...
```

**When to use:**

- Building custom stack discovery tools
- Refreshing cached data
- Most users won't need to call this directly

### ensure_min_version()

Checks if cached stack data was created by a compatible quiltx version.

**Signature:**

```python
def ensure_min_version(
    payload: dict[str, Any] | None,
    min_version: str
) -> bool:
    ...
```

**Parameters:**

- `payload` - Cached stack payload from `load_stack_payload()`
- `min_version` - Minimum required version (e.g., `"0.1.3"`)

**Returns:**

`True` if payload is compatible, `False` otherwise.

**Example:**

```python
from quiltx.stack import load_stack_payload, ensure_min_version
import sys

def main(argv: list[str] | None = None) -> int:
    catalog_name = "example.quiltdata.com"
    payload = load_stack_payload(catalog_name)

    # Check if payload has features added in 0.1.3
    if not ensure_min_version(payload, "0.1.3"):
        print(
            "Stack data outdated. Run 'quiltx stack' to refresh.",
            file=sys.stderr
        )
        return 1

    # Use payload data...
    ecs_resources = payload.get("ecs_resources", {})
    return 0
```

**When to require a minimum version:**

Only require a minimum version when:
- A new field was added to `stack.json` that your tool depends on
- The structure of existing data changed in a breaking way

Example: If version 0.1.2 added `ecs_resources` to the payload, a tool that needs ECS resources should check for `"0.1.2"`.

## Complete Example: Custom Tool

Here's a complete example of building a custom tool using the Stack API:

```python
"""Custom tool to list all log groups."""
import argparse
import sys
from quiltx.stack import load_stack_payload, ensure_min_version
from quiltx import configured_catalog

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List all CloudWatch log groups"
    )
    parser.add_argument(
        "--catalog",
        help="Catalog URL (uses configured catalog if not provided)"
    )
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Get catalog URL
    if args.catalog:
        catalog_url = args.catalog
    else:
        catalog_url = configured_catalog()
        if not catalog_url:
            print("No catalog configured. Run 'quiltx config'.", file=sys.stderr)
            return 1

    # Extract catalog name from URL
    from urllib.parse import urlparse
    catalog_name = urlparse(catalog_url).netloc

    # Load cached stack data
    payload = load_stack_payload(catalog_name)
    if not payload:
        print(
            f"No cached data for {catalog_name}. Run 'quiltx stack'.",
            file=sys.stderr
        )
        return 1

    # Check version compatibility (log_groups added in 0.1.0)
    if not ensure_min_version(payload, "0.1.0"):
        print("Stack data outdated. Run 'quiltx stack'.", file=sys.stderr)
        return 1

    # Display log groups
    log_groups = payload.get("log_groups", [])
    print(f"Found {len(log_groups)} log groups:\n")

    for lg in log_groups:
        logical_id = lg.get("LogicalResourceId", "N/A")
        physical_id = lg.get("PhysicalResourceId", "N/A")
        print(f"  {logical_id:30} -> {physical_id}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## Best Practices

### 1. Prefer Cached Data

Use `load_stack_payload()` instead of `find_matching_stack()` when possible:

```python
# Good: Fast, no AWS calls
payload = load_stack_payload("example.quiltdata.com")

# Less ideal: Slower, requires AWS credentials
stack = find_matching_stack("https://example.quiltdata.com")
```

### 2. Check Version Compatibility

If your tool depends on specific payload fields, check the version:

```python
payload = load_stack_payload(catalog_name)
if not ensure_min_version(payload, "0.1.3"):
    print("Please run 'quiltx stack' to update cached data.")
    return 1
```

### 3. Handle Missing Cache

Always check if cached data exists:

```python
payload = load_stack_payload(catalog_name)
if not payload:
    print("Run 'quiltx stack' first to cache stack data.")
    return 1
```

### 4. Use configured_catalog()

Integrate with quiltx configuration:

```python
from quiltx import configured_catalog

catalog_url = configured_catalog()
if not catalog_url:
    print("Run 'quiltx config' to set catalog.")
    return 1
```

### 5. Provide Helpful Error Messages

Guide users to resolve issues:

```python
if not payload:
    print(
        "Stack data not found. Run:\n"
        "  quiltx stack\n"
        "to cache stack metadata.",
        file=sys.stderr
    )
    return 1
```

## API Reference

For complete API documentation with function signatures and parameters, see the [API Reference](../api/reference.md).
