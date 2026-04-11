# Lake Formation: Glue Database Update Failure

## Date: 2026-04-11

## What Failed

Three consecutive deploys of `stack/bench` failed on CloudFormation stack
update. The error on every attempt:

```text
Resource handler returned message: "Cannot invoke "String.toLowerCase()"
because "databaseName" is null" (HandlerErrorCode: InternalFailure)
```

The failing resources were **Glue Databases**, not LakeFormation grants:

| Resource | Type | Status |
|---|---|---|
| `UserAthenaDatabase` | `AWS::Glue::Database` | UPDATE_FAILED |
| `IcebergDatabase` | `AWS::Glue::Database` | UPDATE_FAILED |
| `AthenaDatabase` | `AWS::Glue::Database` | Update cancelled (rollback) |

## Why We Tried It

The migration ECS task crashed with:

```text
AccessDeniedException: Insufficient Lake Formation permission(s):
  Required Describe on named_packages
```

Database-level `IAM_ALLOWED_PRINCIPALS` grants were already deployed
(`{DB}LFIAMFallthrough`) but they only cover database operations, not table
operations like `GetPartitions`. We needed table-level IAM fallthrough.

We tried three approaches for table-level grants:

1. **TableWildcard** (`{DB}LFIAMFallthroughTables`) — LF rejected:
   `"Grant on table wildcard is not allowed"`

2. **CreateTableDefaultPermissions on DatabaseInput** — the Glue Database
   update crashed (this document). The idea was to set
   `CreateTableDefaultPermissions: [{Principal: IAM_ALLOWED_PRINCIPALS, Permissions: [ALL]}]`
   on each database so future tables would inherit IAM access.

3. **Per-table grants** (`{Table}LFIAMFallthrough`) — also deployed in the same
   commit as #2, so untested in isolation.

## Root Cause of the Database Update Failure

`UserAthenaDatabase` and `IcebergDatabase` were created with empty
`DatabaseInput`:

```python
glue.Database(
    "UserAthenaDatabase",
    CatalogId=Ref("AWS::AccountId"),
    DatabaseInput=glue.DatabaseInput(),  # no Name
)
```

CloudFormation auto-generates the database name when `Name` is omitted. When
we added `CreateTableDefaultPermissions` to the `DatabaseInput`, CloudFormation
attempted to UPDATE the database. The Glue resource handler internally calls
`databaseName.toLowerCase()`, but since `Name` was never explicitly set in the
`DatabaseInput`, the handler receives `null` and throws a Java
`NullPointerException`.

`AthenaDatabase` has an explicit `Name` (computed from `AnalyticsBucket`) so
it would have survived the update, but it was cancelled during rollback.

## Fix

Remove the `CreateTableDefaultPermissions` modification from `lakeformation.py`.
It cannot be added to existing databases that lack an explicit `Name` without
causing this crash. Adding a `Name` retroactively would cause CloudFormation to
REPLACE the database (delete + create), destroying all tables.

The per-table grants (`NamedPackagesAthenaTableLFIAMFallthrough`) are the
correct path for existing CFN-managed tables. For dynamically created tables
(Iceberg, UserAthena), a separate solution is needed — either application-level
LF grants or restoring the account-level `CreateTableDefaultPermissions`.
