# Plan: `quiltx stack acl` command

## Context

Branch `060-stack-acl`. The goal is a new CLI command `quiltx stack acl <file.yml>` that declaratively reconciles a Quilt stack's access control (buckets, policies, roles, SSO) from a YAML file. `quilt3.admin` now exposes the necessary APIs (policies, roles, sso_config, buckets).

## YAML format (spec/060-stack-acl/demo-stack-acl.yml)

```yaml
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

sso:
  - match:
      groups: Everyone
    roles: [visitor]
  - match:
      groups: Employees
    roles: [member]
    admin: true
```

## Mapping to quilt3.admin API

| YAML | Quilt API | Notes |
|------|-----------|-------|
| `bucket_policies.X.read/read_write` buckets | `quilt3.admin.buckets.add(name, title)` | Register buckets on stack |
| `bucket_policies.X` | `quilt3.admin.policies.create_managed(title, permissions)` | 1:1 mapping. `Permission.read(bucket)` / `Permission.read_write(bucket)` |
| `roles.X` | `quilt3.admin.roles.create_managed(name, policies)` | References policy IDs |
| `sso` | `quilt3.admin.sso_config.set(yaml_string)` | Translate simplified match format to Quilt's JSON Schema format |

## Files to create

| File | Purpose |
|------|---------|
| `quiltx/acl.py` | Core library: parse YAML, diff, apply |
| `quiltx/tools/stack/acl.py` | CLI subcommand: argparse, main() |
| `tests/test_acl.py` | Unit tests |

## Files to modify

| File | Change |
|------|--------|
| `quiltx/tools/stack/__init__.py` | Add `"acl"` to `SUBCOMMANDS` dict and `subparsers` |
| `pyproject.toml` | Add `pyyaml` to dependencies |

## Implementation

### Step 1: `quiltx/acl.py` — core library

**Dataclasses:**

- `AclBucketPolicy(name, read: list[str], read_write: list[str])`
- `AclRole(name, bucket_policies: list[str])`
- `AclSsoMapping(match: dict, roles: list[str], admin: bool)`
- `AclConfig(bucket_policies, roles, sso)`

**`parse_acl_config(path) -> AclConfig`** — `yaml.safe_load`, validate structure, cross-reference check (role refs valid policies, SSO refs valid roles).

**`all_buckets(config) -> set[str]`** — collect all bucket names.

**`fetch_current_state() -> CurrentState`** — call `quilt3.admin.{buckets,policies,roles,sso_config}.list()/get()`.

**`compute_diff(desired, current) -> AclDiff`** — compare desired vs current for buckets, policies (by title, match permissions), roles (by name, match policy refs), SSO config. Only touch managed policies/roles. If a desired name collides with an existing **unmanaged** policy or role, emit a warning and skip it (do not overwrite).

**`build_sso_config(mappings) -> str`** — translate simplified `match.groups` to Quilt's JSON Schema SSO format. Does **not** set a `default_role` (omitted to avoid granting unintended access):

```yaml
version: "1.0"
mappings:
  - schema:
      type: object
      properties:
        groups: { type: array, contains: { const: <group> } }
      required: [groups]
    roles: [<role>]
    admin: <bool>
```

**`print_diff(diff)`** — rich output with +/−/~ prefixes.

**`apply_acl(diff)`** — execute in order:

1. Add buckets (`buckets.add`) — if a bucket cannot be added (e.g. not found, permissions error), warn and continue
2. Create/update managed policies (`policies.create_managed` / `policies.update_managed`) — warn and skip on unmanaged name collision
3. Create/update managed roles (`roles.create_managed` / `roles.update_managed`) — warn and skip on unmanaged name collision
4. Update SSO config (`sso_config.set`) — merge/replace mappings but never remove the SSO config entirely
5. Never remove buckets (warn only). Never delete unmanaged roles or policies.

### Step 2: `quiltx/tools/stack/acl.py` — CLI

```
quiltx stack acl <config_file> [--yes]
```

Flow: parse YAML → fetch current state → compute diff → print diff → confirm (or --yes) → apply.

### Step 3: Register subcommand

Add `"acl": "quiltx.tools.stack.acl"` in `quiltx/tools/stack/__init__.py`.

### Step 4: Dependencies

Add `pyyaml` to `pyproject.toml` dependencies.

### Step 5: Tests

Mock `quilt3.admin.*` modules. Test:

- YAML parsing (valid, invalid, cross-ref errors)
- Diff computation (add/update/remove for each entity type, unmanaged entities ignored)
- SSO config translation
- Apply ordering
- CLI integration (help, missing file, --yes flag)

## Safety

1. **No default role** — SSO config omits `default_role` to avoid granting unintended access
2. **No deletion of unmanaged entities** — never delete unmanaged roles or policies; warn on name collision and skip
3. **Warn on bucket failures** — if a bucket cannot be added, warn and continue (do not abort)
4. **SSO config is update-only** — set/replace SSO mappings but never remove the SSO config entirely
5. **Never remove buckets** — warn only
6. **Show full diff** before applying; require `--yes` or interactive confirmation

## Verification

1. `./poe test` — unit tests pass
2. Manual: create a test YAML, run `quiltx stack acl test.yml` against a dev stack, verify diff output
3. Manual: run with `--yes`, verify policies/roles/SSO created via Quilt admin UI
4. Re-run same file — should print "Stack ACL is up to date"
