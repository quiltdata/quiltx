# Spec: `quiltx ecs` subcommand restructure + `run-migration`

## Date: 2026-04-11

## Problem

When the migration ECS task fails during a stack deploy (e.g., due to Lake
Formation permission errors as described in
[02-lakeformation-post-mortem.md](02-lakeformation-post-mortem.md)), there is
no trivial way to re-run it. The migration is normally triggered by a
CloudFormation custom resource (`MigrationCallout`) which invokes a Lambda
(`MigrationLambdaFunction`) that calls `ecs.run_task()`. Re-triggering requires
either a full stack update or manually constructing the `run_task` call with the
correct task definition, network configuration, and launch parameters.

## Goal

Restructure `quiltx ecs` as a subcommand dispatcher (like `quiltx stack`) and
add a `run-migration` subcommand. We are pre-1.0 so this is the right time to
make breaking changes.

```shell
quiltx ecs shell          # existing interactive shell (was: quiltx ecs)
quiltx ecs run-migration  # new: re-run the registry migration task
```

### Breaking change

`quiltx ecs [service]` becomes `quiltx ecs shell [service]`. The bare
`quiltx ecs` now prints subcommand help instead of launching a shell.

## Architecture: How the Migration Works Today

1. **MigrationLambdaFunction** (Python 3.11, `index.handler`) is a CFN custom
   resource handler invoked by `MigrationCallout` during stack create/update
2. The Lambda calls `ecs.run_task()` with:
   - **Task definition:** `{stack_name}-registry-migration` (Fargate, `awsvpc`)
   - **Container:** `registry_migration`
   - **Network config:** subnets and security groups from the CFN event
   - **Launch type:** `FARGATE`
3. The migration container runs alembic DB migrations, then
   `update_bucket_resources` (which calls `rebuild_named_packages_partitions`)
4. Logs go to CloudWatch log group `{stack_name}` with stream prefix
   `registry/registry_migration/`

### Observed on `tf-dev-bench` (us-east-2)

| Resource | Value |
| --- | --- |
| Lambda | `tf-dev-bench-MigrationLambdaFunction-4YhmruZjSrAz` |
| Task definition | `tf-dev-bench-registry-migration:9` |
| Container name | `registry_migration` |
| Log group | `tf-dev-bench` |
| Log stream prefix | `registry/registry_migration/` |
| Cluster | `tf-dev-bench` |
| Network mode | `awsvpc` (Fargate) |
| CPU / Memory | 512 / 2048 |

## Design

### Structure: `quiltx ecs` as a subcommand dispatcher

Convert `quiltx/tools/ecs.py` from a flat module into a package
`quiltx/tools/ecs/` following the same pattern as `quiltx/tools/stack/`:

```
quiltx/tools/ecs/
    __init__.py        # subcommand dispatcher (SUBCOMMANDS dict, build_parser, main)
    shell.py           # existing interactive shell (moved from ecs.py)
    run_migration.py   # new: run the migration ECS task
```

`__init__.py` uses `argparse` subparsers and `importlib.import_module()` to
dispatch, identical to `quiltx/tools/stack/__init__.py`. The CLI auto-discovery
in `cli.py` already handles packages (via `pkgutil.iter_modules`), so no
changes needed there.

Shared helpers (catalog resolution, stack payload loading, ECS resource
extraction) stay in `shell.py` or move to a private `_common.py` if both
subcommands need them. For now, `run_migration.py` can import directly from
`shell` since the helpers are simple.

### Discovery

1. Resolve catalog name (same as existing `quiltx ecs` flow)
2. Load stack payload to get `stack_name`, `region`, and cluster
3. Find the migration task definition via ECS API:
   `list_task_definitions(familyPrefix="{stack_name}-registry-migration", sort="DESC")`
4. Get network configuration from the **RegistryService** in the cluster (see
   "Network config selection" below)

### Network config selection

The migration task must land in the same subnets/security groups as the registry
so it can reach the RDS database and Glue/Lake Formation endpoints. Clusters can
contain services with different networking (e.g., a Benchling webhook service
with its own SGs), so picking an arbitrary service is not safe.

Strategy:

1. Look up `RegistryService` in the cached stack payload `ecs_resources`
2. Call `describe_services` on that service to get its `networkConfiguration`
3. If `RegistryService` is not in the payload, fall back to the first service
   whose logical ID contains `Registry` (case-insensitive)
4. If no registry service is found, error with a message suggesting
   `--network-config` (future escape hatch) or `quiltx stack cfn` to refresh

### Execution

Call `ecs.run_task()` with:

```python
{
    "cluster": cluster,
    "taskDefinition": task_def_arn,
    "launchType": "FARGATE",
    "networkConfiguration": network_config,  # from RegistryService
    "propagateTags": "TASK_DEFINITION",
    "enableECSManagedTags": True,
}
```

No container overrides are needed -- the task definition already contains all
required environment variables.

### Launch failure handling

`ecs.run_task()` can return HTTP 200 with a non-empty `failures` list and no
task ARN. This happens for IAM denials, invalid networking, capacity issues, etc.
-- exactly the class of problems this command is meant to recover from.

`run_migration()` must:

1. Check `response["failures"]` before accessing `response["tasks"]`
2. If failures are present, raise `MigrationLaunchError` with the failure
   reasons (each entry has `arn`, `reason`, `detail`)
3. The CLI prints each failure reason and exits non-zero
4. The public API raises `MigrationLaunchError` so callers can inspect `.failures`

### Flags

| Flag | Behavior |
| --- | --- |
| `--catalog` | Catalog name or URL (same as `quiltx ecs`) |
| `--region` | AWS region override (defaults to stack payload) |
| `--dry-run` | Print `run_task` parameters as JSON, do not execute |
| `--no-wait` | Fire and forget; skip polling for task completion |

### Wait behavior (default)

By default the command waits for the migration to finish. Uses the
`tasks_stopped` ECS waiter (polls every 10s, up to 60 attempts = 10
minutes). After the task stops:

- Exit code 0 from the container -> success
- Non-zero exit code -> print `stoppedReason` and `stopCode`, exit non-zero
- Print a hint to check logs via `quiltx logs`

Pass `--no-wait` to start the task and return immediately.

## Public API: `quiltx.ecs`

Following the project convention (library in `quiltx/`, CLI in `quiltx/tools/`),
the reusable functions live in `quiltx/ecs.py` so scripts can embed migration
runs in a workflow:

```python
from quiltx.ecs import find_migration_task_def, get_network_config, run_migration

# Low-level: find resources yourself
task_def = find_migration_task_def(ecs_client, "tf-dev-bench")
net_config = get_network_config(ecs_client, "tf-dev-bench", stack_payload)
task = run_migration(ecs_client, cluster, task_def, net_config)

# High-level: one-call convenience
from quiltx.ecs import run_migration_for_catalog
result = run_migration_for_catalog("bench.dev.quilttest.com", wait=True)
# result.exit_code, result.task_arn, result.stopped_reason
```

## Files to create

| File | Purpose |
| --- | --- |
| `quiltx/ecs.py` | Public library: task def discovery, network config, run_task |
| `quiltx/tools/ecs/__init__.py` | Subcommand dispatcher (same pattern as `stack/__init__.py`) |
| `quiltx/tools/ecs/shell.py` | Existing interactive shell logic (moved from `tools/ecs.py`) |
| `quiltx/tools/ecs/run_migration.py` | CLI subcommand (thin wrapper around `quiltx.ecs`) |

## Files to modify

| File | Change |
| --- | --- |
| `quiltx/tools/ecs.py` | **Delete** (replaced by `ecs/` package) |
| `tests/test_ecs.py` | Update imports, add tests for new helpers |

## Public functions in `quiltx/ecs.py`

| Function | Purpose |
| --- | --- |
| `find_migration_task_def(ecs_client, stack_name) -> str` | List task defs, return latest ARN |
| `get_network_config(ecs_client, cluster, stack_payload) -> dict` | Get `awsvpcConfiguration` from RegistryService |
| `run_migration(ecs_client, cluster, task_def, network_config) -> dict` | Call `run_task`, return task dict; raises `MigrationLaunchError` on failures |
| `wait_for_task(ecs_client, cluster, task_arn) -> MigrationResult` | Poll until stopped, return result |
| `run_migration_for_catalog(catalog, *, wait=True) -> MigrationResult` | High-level convenience |

`MigrationResult` is a dataclass with `task_arn`, `exit_code`, `stopped_reason`,
`stop_code`.

`MigrationLaunchError` is raised when `run_task()` returns failures instead of a
task. Has a `.failures` attribute (list of dicts with `arn`, `reason`, `detail`).

## Test plan

| Test | What it verifies |
| --- | --- |
| `test_find_migration_task_def` | Returns latest ARN from stubbed `list_task_definitions` |
| `test_find_migration_task_def_not_found` | Raises `ValueError` when no task defs match |
| `test_get_network_config_prefers_registry` | Picks `RegistryService` when multiple services exist |
| `test_get_network_config_no_registry` | Errors when no registry-like service is found |
| `test_run_migration_launch_failure` | `run_migration()` raises `MigrationLaunchError` when `response["failures"]` is non-empty |
| `test_run_migration_success` | Returns task dict when `response["tasks"]` is populated |
| `test_ecs_shell_imports_unchanged` | Existing `test_ecs.py` tests pass with updated imports |

## Files to update

| File | Change |
| --- | --- |
| `README.md` | Document `quiltx ecs shell` / `quiltx ecs run-migration` CLI usage |
| `README.md` | Document `quiltx.ecs` public API for scripting |

## Open questions

- [ ] Should we also support re-running `TrackingCallout` (the `stack-status`
      task)? Same mechanism, different task definition family.
- [ ] Should we stream CloudWatch logs inline instead of (or in addition to)
      the `--wait` polling approach?
