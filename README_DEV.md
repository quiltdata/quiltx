# quiltx Python API

Programmatic interfaces for `quiltx` modules. For CLI usage see [README.md](README.md).

## Config and stack

```python
from quiltx import get_catalog_url, get_catalog_region, set_catalog_url
from quiltx.stack import find_matching_stack

set_catalog_url("https://open.quiltdata.com")
print(get_catalog_url())     # https://open.quiltdata.com
print(get_catalog_region())  # us-east-1

stack = find_matching_stack(get_catalog_url())
print(stack["StackName"])
```

## ECS

```python
import boto3

from quiltx.ecs import describe_service_status, run_migration_for_catalog

result = run_migration_for_catalog("https://open.quiltdata.com", wait=True)
print(result.task_arn)
print(result.exit_code)

ecs_client = boto3.client("ecs", region_name="us-east-1")
status = describe_service_status(ecs_client, cluster="quilt", service="registry-service")
print(status.stable)
```

## Stack ACL

```python
from quiltx import apply_acl, compute_diff, fetch_current_state, parse_acl_config, print_diff

# config.yml now uses the flat stack ACL format:
#   top-level policies: and roles:
config = parse_acl_config("config.yml")
current = fetch_current_state()
diff = compute_diff(config, current)
print_diff(diff, verbose=True, desired=config, current=current)

if diff.has_changes():
    apply_acl(diff, current)
```
