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

## Bucket registration paths

Bucket registration has three explicit paths. The default bucket-owner path and
ACL reconciliation both call the same AWS preparation planner/applicator to
probe S3, merge the Quilt bucket-policy statement, configure SNS, and configure
bucket notifications; they then call GraphQL `bucketAdd` with the planned SNS
topic ARN.

`quiltx bucket prepare` calls that same planner/applicator but is AWS-only and must remain outside `catalog_command`.
It reads and converges the final bucket policy, SNS policy, and notification
document without loading catalog configuration or calling Quilt admin APIs.
An optional `--catalog DNS` derives the control account ID when
`--control-account-id`/`--principal` are omitted: cached stack metadata wins;
otherwise it logs in as a regular catalog user (no admin role) and asks STS
which account minted the catalog credentials. That is the only catalog touch
prepare is allowed. The bucket owner can emit a minimal `--json --yes` handoff;
the catalog operator completes registration separately with
`quiltx bucket add BUCKET --catalog DNS --no-preflight`. `--dry-run` performs
AWS reads but no writes and prints the exact three final documents. Notification
overlap must fail before any write so unrelated Topic, Queue, Lambda, and
EventBridge configuration is never replaced.

The `--no-preflight` path is GraphQL-only. It skips local S3/SNS calls and
submits `bucketAdd` without an SNS ARN so the catalog stack probes the bucket
with its own IAM, matching the admin UI behavior. Use this for public buckets
or buckets already configured outside the caller's local AWS account.

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
