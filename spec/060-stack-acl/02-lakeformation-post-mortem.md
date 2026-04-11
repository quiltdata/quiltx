# Lake Formation Post-Mortem: `stack acl` Failures on bench.dev

## Date: 2026-04-10

## Summary

All `quiltx stack acl` operations fail with "Internal Server Error" on the
`tf-dev-bench` stack (`bench.dev.quilttest.com`). The root cause is that AWS
Lake Formation account-level settings were changed (likely by the `sus-test`
branch), removing `IAMAllowedPrincipals` defaults and silently enabling LF
enforcement across all Glue databases in the account. The Quilt stack never
opted into Lake Formation and has no LF grants for its service roles.

## Root Cause

### Account-level Lake Formation settings

The `CreateDatabaseDefaultPermissions` and `CreateTableDefaultPermissions` are
both empty (`[]`). This removes the `IAMAllowedPrincipals` fallthrough that
normally lets IAM-only roles access Glue resources without explicit LF grants.

LF admins include `sus-test-managed-access` and `sus-test-provisioning` roles,
indicating the `sus-test` work modified these account-level defaults.

### Affected principal

The registry ECS task role
(`tf-dev-bench-AmazonECSTaskExecutionRole-sldeHlgF9O51`) had **zero** Lake
Formation grants, despite having full IAM permissions for Glue. LF enforcement
overrides IAM.

## Failure Cascade

1. **Bucket add** calls `CreatePartition` on `named_packages`
   - LF blocks with: `Insufficient Lake Formation permission(s): Required Alter on named_packages`

2. **Bucket add** also runs an Athena `MERGE INTO package_revision` query
   - LF blocks Athena access to `icebergdatabase-brfcry2g6wwi`
   - Even after LF grants: `Table package_revision not found` (Iceberg database is empty -- migration likely also blocked by LF)

3. **Policy create** fails with `ForeignKeyViolation` on `role_policy_bucket_permission`
   - Buckets never registered in the DB, so policy FK constraint fails

4. **Role create** fails because policies don't exist

5. **SSO config** fails with `RolesNotFound` because roles don't exist

## Affected Databases

| Glue Database | Used For |
|---|---|
| `tf_dev_bench_analyticsbucket_3uiiyxb9hcbs` | `named_packages` table (package analytics) |
| `userathenadatabase-zbotoxulpf53` | Per-bucket Athena tables (user queries) |
| `icebergdatabase-brfcry2g6wwi` | `package_revision` Iceberg table |
| `icebergdatabase-ypxc3vjuoicc` | Secondary Iceberg database |

## Manual LF Grants Applied (partial fix)

Granted `ALTER`, `INSERT`, `DELETE`, `DESCRIBE`, `SELECT`, `DROP`, `ALL` to
the registry task role on all four databases and their tables. This resolved
the LF `AccessDenied` errors but exposed the missing `package_revision` Iceberg
table -- the Iceberg database is completely empty, suggesting the migration
Lambda also failed due to LF.

## Open Questions

- [x] Was the migration Lambda also blocked by LF? **Yes.** The migration ECS
      task (`registry_migration/29d0ec39d920`) ran all alembic DB migrations
      successfully but crashed in `update_bucket_resources` →
      `rebuild_named_packages_partitions()` with:
      `AccessDeniedException: Insufficient Lake Formation permission(s): Required Describe on named_packages`
      (CloudWatch log group: `tf-dev-bench`, stream:
      `registry/registry_migration/29d0ec39d9204bd689a081522d4dced5`)
- [x] Should the Quilt stack template grant LF permissions to its own roles?
      **Yes.** Database-level `IAM_ALLOWED_PRINCIPALS` grants were added in
      `a933417` but are insufficient — table-level `TableWildcard` grants are
      also required because the account-level `CreateTableDefaultPermissions`
      is empty. Fix applied: `lakeformation.py` now creates both database and
      table-wildcard grants. `MigrationCallout.DependsOn` updated to include
      all LF resources so the migration cannot race ahead of the grants.
- [ ] Can we re-run the migration to create the `package_revision` table?
- [ ] Should the `sus-test` LF changes be scoped to only `sus-test` databases
      rather than changing account-wide defaults?
- [ ] Are other stacks in this account (`tf-dev-unstable`, `tf-dev-mcp-server`)
      also affected?

## Recommendations

1. **Immediate**: Re-run the migration Lambda after granting it LF permissions,
   then retry `stack acl`
2. **Short-term**: Either restore `IAMAllowedPrincipals` as the account default,
   or have the stack template (deployment repo) grant LF permissions to all
   service roles
3. **Long-term**: If `sus-test` needs LF enforcement, scope it to its own
   databases via LF tags or resource-level grants rather than changing
   account-wide defaults
