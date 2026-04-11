# Lake Formation: Current Status

## Date: 2026-04-11 (updated after `70fa6ae` deploy)

For commit history, see [03-lakeformation-fixes.md](03-lakeformation-fixes.md).
For the database update failure, see [06-lakeformation-db-fail.md](06-lakeformation-db-fail.md).

## LF Grant Mechanisms Tried

| Mechanism | Works? | Notes |
|---|---|---|
| IAM_ALLOWED_PRINCIPALS on **database** | Yes | Covers DB-level ops only |
| IAM_ALLOWED_PRINCIPALS on **TableWildcard** | **No** | `Grant on table wildcard is not allowed` |
| IAM_ALLOWED_PRINCIPALS on **specific table** | **Yes** | Deployed in `70fa6ae` |
| `CreateTableDefaultPermissions` on `DatabaseInput` | **No** | Crashes DBs with auto-generated names (see 06) |

## What's Deployed in `lakeformation.py`

1. **Database-level LF grants** (`{DB}LFIAMFallthrough`)
   - IAM_ALLOWED_PRINCIPALS -> ALL on each database

2. **Per-table LF grant** (`NamedPackagesAthenaTableLFIAMFallthrough`)
   - IAM_ALLOWED_PRINCIPALS -> ALL on `named_packages` table
   - `AuditTrailTable` grant activates only in variants with audit trail

Plus: `MigrationCallout.DependsOn` includes all LF resources.

## What's Left

1. **Re-run migration** on `tf-dev-bench` — see [04-run-migration.md](04-run-migration.md)
2. **Verify `stack acl`** — `quiltx stack acl demo-stack-acl.yml --yes`
3. **Dynamically created tables** (Iceberg, UserAthena) still have no LF grants;
   `CreateTableDefaultPermissions` can't be added to existing nameless DBs.
   Options: restore account-level defaults, or grant in application code.
4. **Account-level defaults** — `sus-test` emptied `CreateTableDefaultPermissions`
   account-wide; restoring would fix items 1-3 for all stacks at once
5. **Other stacks** — `tf-dev-unstable`, `tf-dev-mcp-server` etc. need same template
