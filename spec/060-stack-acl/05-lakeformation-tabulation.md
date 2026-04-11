# Lake Formation: Current Status

## Date: 2026-04-11

For commit history, see [03-lakeformation-fixes.md](03-lakeformation-fixes.md).

## LF Grant Mechanisms Tried

| Mechanism | Works? | Notes |
|---|---|---|
| IAM_ALLOWED_PRINCIPALS on **database** | Yes | Covers DB-level ops only |
| IAM_ALLOWED_PRINCIPALS on **TableWildcard** | **No** | `InvalidInputException: Grant on table wildcard is not allowed` |
| IAM_ALLOWED_PRINCIPALS on **specific table** | Pending | Covers table-level ops for CFN-managed tables |
| `CreateTableDefaultPermissions` on `DatabaseInput` | Pending | Covers dynamically created tables |

## Three Layers in `lakeformation.py`

1. **Database-level LF grants** (`{DB}LFIAMFallthrough`)
   - IAM_ALLOWED_PRINCIPALS -> ALL on each database

2. **Per-table LF grants** (`{Table}LFIAMFallthrough`)
   - IAM_ALLOWED_PRINCIPALS -> ALL on `NamedPackagesAthenaTable`, `AuditTrailTable`

3. **CreateTableDefaultPermissions** on each Glue database
   - Future tables (Iceberg, UserAthena) inherit IAM_ALLOWED_PRINCIPALS

Plus: `MigrationCallout.DependsOn` includes all LF resources.

## What's Left

1. **Deploy `27f5aa8`** (per-table grants) — pending CI
2. **Re-run migration** on `tf-dev-bench` — see [04-run-migration.md](04-run-migration.md)
3. **Verify `stack acl`** — `quiltx stack acl demo-stack-acl.yml --yes`
4. **Account-level defaults** — `sus-test` emptied `CreateTableDefaultPermissions`
   account-wide; consider restoring or scoping to `sus-test` databases only
5. **Other stacks** — `tf-dev-unstable`, `tf-dev-mcp-server` etc. need same template
