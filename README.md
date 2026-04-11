# quiltx

[![PyPI](https://img.shields.io/pypi/v/quiltx)](https://pypi.org/project/quiltx/)

Quilt extension toolkit for working with [Quilt](https://quiltdata.com) catalogs.

## Quick start

```bash
# See available tools
uvx quiltx

# Configure a Quilt catalog
uvx quiltx stack catalog https://open.quiltdata.com

# Get help for any tool
uvx quiltx <tool> --help
```

## Tools

- **bucket** — Register cross-account S3 buckets with Quilt (policy, SNS, notifications)
- **ecs** — ECS task tools:
  - **ecs shell** — Interactive shell access to running ECS tasks via Session Manager
  - **ecs run-migration** — Re-run the registry migration task for a stack
- **logs** — Display and tail CloudWatch logs for the configured catalog
- **stack** — Manage Quilt stack:
  - **stack acl** — Declarative access-control-list (ACL) reconciliation from YAML
  - **stack catalog** — Configure and display Quilt catalog settings
  - **stack cfn** — Discover the Quilt CloudFormation stack and cache metadata

## ECS CLI

```bash
# Open an interactive shell inside the registry service task
uvx quiltx ecs shell

# Dry-run the registry migration relaunch using cached stack metadata
uvx quiltx ecs run-migration --dry-run

# Start the migration task and wait for completion
uvx quiltx ecs run-migration
```

## ECS Python API

```python
from quiltx.ecs import run_migration_for_catalog

result = run_migration_for_catalog("https://open.quiltdata.com", wait=True)
print(result.task_arn)
print(result.exit_code)
```

## Stack ACL

`quiltx stack acl` declaratively manages a Quilt stack's access control lists
(ACLs) — buckets, policies, roles, and SSO mappings — from a single YAML file.
Instead of clicking through the catalog admin UI, you define the desired state
in version-controlled YAML and let the tool reconcile it against the server.

### YAML example

```yaml
# Access control lists for a Quilt stack
bucket_policies:
  public:
    read:
      - quilt-example
  internal:
    read_write:
      - quilt-bake
      - quilt-dev
    read:
      - quilt-leadership

roles:
  visitor:
    bucket_policies: [public]
  member:
    bucket_policies: [public, internal]
    default: true          # assigned to new users

sso:
  - match:
      groups: Employees
    roles: [member]
    admin: true
  - match:
      groups: Everyone
    roles: [visitor]
```

### CLI usage

```bash
# Show current server ACL state
uvx quiltx stack acl

# Preview changes (dry run)
uvx quiltx stack acl config.yml --dry-run

# Preview with full detail
uvx quiltx stack acl config.yml --dry-run --verbose

# Apply changes (with confirmation prompt)
uvx quiltx stack acl config.yml

# Apply without prompting
uvx quiltx stack acl config.yml --yes
```

### Python API

```python
from quiltx import (
    parse_acl_config,
    fetch_current_state,
    compute_diff,
    print_diff,
    apply_acl,
)

config = parse_acl_config("config.yml")
current = fetch_current_state()
diff = compute_diff(config, current)
print_diff(diff, verbose=True, desired=config, current=current)

if diff.has_changes():
    apply_acl(diff, current)
```

## Config and stack API

```python
from quiltx import get_catalog_url, get_catalog_region, set_catalog_url
from quiltx.stack import find_matching_stack

set_catalog_url("https://open.quiltdata.com")
print(get_catalog_url())     # https://open.quiltdata.com
print(get_catalog_region())  # us-east-1

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
