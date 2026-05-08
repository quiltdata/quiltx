---
title: "Stack/context refactor checklist"
branch: "46-quiltx-ecs-log-level"
---

Goal
----

Make catalog lookup, auth mode, stack discovery, AWS region selection, and ECS
resource extraction follow one shared path across `catalog`, `ecs`, and bucket
operations. Log viewing is an `ecs logs` subcommand, not a separate command
domain.

Problem
-------

`catalog` commands can resolve the target catalog and often proceed without a
cached stack payload, while some `ecs` commands still expect `stack.json` to
already exist. That creates inconsistent UX and duplicated recovery guidance.

Checklist
---------

- [x] Keep `stack.catalog_command` as the only CLI catalog resolver for commands
      that accept `--catalog`.
- [x] Centralize stack payload lifecycle in `quiltx.stack`:
      load cached payload, discover from catalog config + CloudFormation,
      refresh cache, and require known fields.
- [x] Replace direct command calls to `load_stack_payload` /
      `require_stack_payload` with `ensure_stack_payload` unless the command
      explicitly needs cache-only behavior.
- [x] Make `quiltx catalog stack` the explicit refresh command, backed by the
      same discovery helper used by auto-discovering commands.
- [x] Add typed accessor helpers for common payload fields:
      `require_region`, `require_stack_name`, `ecs_clusters`, `ecs_services`,
      `registry_service`, and `log_groups`.
- [x] Move `ecs shell`, `ecs logs`, `ecs run-migration`, and `quiltx.ecs`
      helpers onto those accessors instead of parsing payload shape locally.
- [x] Move bucket operations onto the shared stack helper path while preserving
      the current lightweight fallback for commands that can proceed without a
      CloudFormation stack match.
- [x] Centralize AWS client construction so each command does not separately
      choose between cached region, fetched region, and ambient boto3 defaults.
- [x] Define command policy once:
      read-only inspection commands auto-discover; mutating commands
      auto-discover then fail with exact permission/remediation guidance;
      `catalog stack` always refreshes.
- [x] Route log-level mutations through the same catalog, stack, region, and ECS
      resource helpers as log viewing; do not hardcode registry service or bypass
      stack discovery when `ecs logs --set-level` performs an update.
- [x] Preserve auth separation:
      registry/admin operations use catalog API auth; CloudFormation,
      CloudWatch, and ECS operations use the ambient AWS credential chain.
- [x] Update tests to assert behavior, not historical error text:
      missing cache should auto-discover where expected, and cache-only
      commands should be explicit exceptions.

Guardrails
----------

- Do not introduce a new persistent config format.
- Do not mix Quilt API keys into AWS credential resolution.
- Do not reintroduce a distinct top-level `logs` command path; log viewing and
  log-level changes belong under `ecs`.
- Keep each CLI command thin: parse args, call shared context/resource helpers,
  perform the operation, render output.

Suggested Order
---------------

After each stage, lint, test, commit, and push

1. [x] Add stack payload requirement/accessor helpers with unit tests.
2. [x] Migrate `ecs logs` and `catalog stack` first because they expose the current
   inconsistency.
3. [x] Migrate `ecs logs --set-level` onto the shared context path before replacing
   the placeholder implementation.
4. [x] Migrate `ecs shell` list/default selection.
5. [x] Migrate `run-migration` and `quiltx.ecs` helpers.
6. [x] Migrate bucket operations, including the lightweight fallback policy.
7. [x] Remove duplicate missing-cache messages and payload parsing branches.
8. [x] Update README and AGENTS docs if necessary (keep concise)

Verification
------------

- [x] `./poe lint-check`
- [x] `./poe test` (286 passed, 1 skipped)
