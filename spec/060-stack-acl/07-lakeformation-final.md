# Lake Formation: Problem & Solution

## Problem

When Lake Formation enforcement is active at the AWS account level
(i.e. `IAMAllowedPrincipals` removed from `CreateDatabaseDefaultPermissions`),
IAM-only roles lose access to Glue resources even if their IAM policies allow it.
This silently breaks all Glue/Athena operations for the registry, migration task,
and other stack services.

The stack creates four Glue databases and two CFN-managed tables:

| Resource | Module | Conditional? |
|---|---|---|
| `AthenaDatabase` | analytics.py | no |
| `UserAthenaDatabase` | user_athena.py | no |
| `IcebergDatabase` | iceberg.py | no |
| `AuditTrailDatabase` | audit_trail.py | yes (audit_trail flag) |
| `NamedPackagesAthenaTable` | analytics.py | no |
| `AuditTrailTable` | audit_trail.py | yes |

Two additional databases (`UserAthenaDatabase`, `IcebergDatabase`) have
auto-generated names (empty `DatabaseInput`), which limits what CloudFormation
can safely modify on them.

## Solution

New module: `t4/template/lakeformation.py` (called from `entry.py`).

### 1. Database-level grants

For each database present in the template, create an
`AWS::LakeFormation::Permissions` resource granting
`IAM_ALLOWED_PRINCIPALS` -> `ALL` on the database:

```
{DB}LFIAMFallthrough  ->  DatabaseResource(Name=Ref({DB}))
```

This restores IAM access for database-level operations (e.g. `GetDatabase`,
`GetTables`) regardless of account-level LF settings.

### 2. Per-table grants

For each CFN-managed Glue table (`NamedPackagesAthenaTable`,
`AuditTrailTable`), create an explicit `AWS::LakeFormation::Permissions`
granting `IAM_ALLOWED_PRINCIPALS` -> `ALL` on the table.

Table and database names are extracted directly from the Glue Table resource
properties (not via `Ref` on the table, which doesn't resolve correctly in
the LF handler context).

### 3. Migration ordering

`add_iam_fallthrough()` returns the logical IDs of all LF resources it
creates. `entry.py` appends these to `MigrationCallout.DependsOn` so the
migration ECS task runs only after grants are in place.

### 4. Conditional resources

Both database and table grant loops skip resources not present in
`cft.resources`, so conditional resources (AuditTrail) are handled
automatically without checking environment flags.

## Constraints

| Approach | Why it doesn't work |
|---|---|
| `TableWildcard` grant | LF rejects: "Grant on table wildcard is not allowed" |
| `CreateTableDefaultPermissions` on `DatabaseInput` | Crashes auto-named DBs with NPE: `databaseName is null` |

## Open Items

- **Dynamically created tables** (Iceberg partition tables, UserAthena
  per-bucket tables) have no LF grants. They are created at runtime, not by
  CloudFormation, so per-table CFN grants can't cover them. Options:
  grant in application code, or restore account-level defaults.
- **Account-level defaults** could be restored to fix all stacks at once,
  but that reverses the tighter posture introduced by `sus-test`.
