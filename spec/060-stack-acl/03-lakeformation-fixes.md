# Lake Formation Fixes in Deployment Repo

## Date: 2026-04-10 (updated 2026-04-11)

## Context

After discovering that account-level Lake Formation settings broke all
`quiltx stack acl` operations (see [02-lakeformation-post-mortem.md](02-lakeformation-post-mortem.md)),
the following fixes were applied in the deployment repo (`t4/template/`).

## Commits (newest first)

### 1. `cb88ede` — check template resources instead of env for conditional databases

- **Author:** Dr. Ernie Prabhakar
- **Date:** 2026-04-10 11:23:14 -0700
- **Files:** `entry.py`, `lakeformation.py`
- **What:** Use `cft.resources` to determine which databases exist rather than
  re-checking env flags. This is robust against stack variants where database
  existence doesn't match a simple flag check.

### 2. `c530ad5` — make AuditTrailDatabase LF grant conditional on audit_trail

- **Author:** Dr. Ernie Prabhakar
- **Date:** 2026-04-10 11:16:46 -0700
- **Files:** `entry.py`, `lakeformation.py`
- **What:** `AuditTrailDatabase` only exists when `env.options.audit_trail` is
  true, so the LF grant must be conditional to avoid cfn-lint E1020 errors in
  stack variants without audit trail.

### 3. `c71afce` — fix ruff formatting in lakeformation.py

- **Author:** Dr. Ernie Prabhakar
- **Date:** 2026-04-10 11:10:40 -0700
- **Files:** `lakeformation.py`
- **What:** Style/formatting fix only.

### 4. `a933417` — opt Glue databases out of Lake Formation enforcement (primary fix)

- **Author:** Dr. Ernie Prabhakar
- **Date:** 2026-04-10 11:06:59 -0700
- **Files:** `entry.py` (6 lines), `lakeformation.py` (43 lines, **new file**)
- **What:** Add `IAM_ALLOWED_PRINCIPALS` grants on all stack-created Glue
  databases so that IAM-only roles retain access regardless of account-level LF
  settings. Without this, removing `IAMAllowedPrincipals` from
  `CreateDatabaseDefaultPermissions` silently breaks all Glue/Athena operations
  for the registry, migration Lambda, and other stack services.

## Prior Attempt (reverted)

### `8cc8266` — Fix Glue db/tables permissions with non-default LF settings (#1831)

- **Author:** Sergey Fedoseev
- **Date:** 2025-09-15
- **Files:** `analytics.py`, `audit_trail.py`, `containers.py`, `helpers.py`
  (75 lines added), `user_athena.py`
- **Status:** Reverted in `14f0ba6` (2025-09-16)
- **What:** Earlier attempt that placed LF grant logic inline in each module's
  file. Reverted the next day; reason not recorded in commit message.

## 2026-04-11: Database-level grants insufficient

The 2026-04-10 fix added database-level `IAM_ALLOWED_PRINCIPALS` grants, but
`stack acl` still fails with `Internal Server Error` on all bucket adds. Root
cause confirmed via migration ECS task logs:

```text
AccessDeniedException: Insufficient Lake Formation permission(s):
  Required Describe on named_packages
```

**Why database grants alone don't work:** The account-level
`CreateTableDefaultPermissions` is empty (`[]`), so new tables created in Glue
do NOT inherit `IAM_ALLOWED_PRINCIPALS`. Table operations (`GetPartitions`,
`CreatePartition`, etc.) require table-level grants.

### Additional fixes applied (2026-04-11)

**`lakeformation.py`:**

- Added `TableWildcard` grants alongside each database grant — covers all
  current and future tables in each database
- Function now returns list of created resource titles (for DependsOn wiring)

**`entry.py`:**

- `MigrationCallout.DependsOn` now includes all LF grant resources, preventing
  the migration ECS task from racing ahead of the LF grants during stack
  creation

## Implementation Summary

The fix lives in `t4/template/lakeformation.py`. For each Glue database the
stack creates, it adds two `AWS::LakeFormation::Permissions` resources:

| Grant | Resource | Purpose |
|---|---|---|
| Database-level | `{DB}LFIAMFallthrough` | IAM fallthrough for DB operations |
| Table-wildcard | `{DB}LFIAMFallthroughTables` | IAM fallthrough for all tables |

Covered databases:

| Database | Source Module | Conditional? |
|---|---|---|
| `AthenaDatabase` | `analytics.py` | No |
| `UserAthenaDatabase` | `user_athena.py` | No |
| `IcebergDatabase` | `iceberg.py` | No |
| `AuditTrailDatabase` | `audit_trail.py` | Yes (audit_trail enabled) |

The module iterates `_DATABASE_TITLES` and skips any database not present in
`cft.resources`, making it safe for all stack variants. `MigrationCallout`
depends on all LF resources to ensure correct ordering.

## Verification

- `make test` — 41 passed
- `make lint-cfn` — clean (only pre-existing W2010 on `SingleSignOnClientSecret`)
