---
title: "Stack/context refactor checklist"
branch: "46-quiltx-ecs-log-level"
---

Goal
----

Make catalog lookup, auth mode, stack discovery, AWS region selection, and ECS
resource extraction follow one shared path across `catalog`, `ecs`, `logs`, and
bucket operations.

Problem
-------

`catalog` commands can resolve the target catalog and often proceed without a
cached stack payload, while some `ecs` commands still expect `stack.json` to
already exist. That creates inconsistent UX and duplicated recovery guidance.

Checklist
---------

- [ ] Keep `stack.catalog_command` as the only CLI catalog resolver for commands
      that accept `--catalog`.
- [ ] Centralize stack payload lifecycle in `quiltx.stack`:
      load cached payload, discover from catalog config + CloudFormation,
      refresh cache, and require known fields.
- [ ] Replace direct command calls to `load_stack_payload` /
      `require_stack_payload` with `ensure_stack_payload` unless the command
      explicitly needs cache-only behavior.
- [ ] Make `quiltx catalog stack` the explicit refresh command, backed by the
      same discovery helper used by auto-discovering commands.
- [ ] Add typed accessor helpers for common payload fields:
      `require_region`, `require_stack_name`, `ecs_clusters`, `ecs_services`,
      `registry_service`, and `log_groups`.
- [ ] Move `ecs shell`, `ecs logs`, `ecs run-migration`, and `quiltx.ecs`
      helpers onto those accessors instead of parsing payload shape locally.
- [ ] Centralize AWS client construction so each command does not separately
      choose between cached region, fetched region, and ambient boto3 defaults.
- [ ] Define command policy once:
      read-only inspection commands auto-discover; mutating commands
      auto-discover then fail with exact permission/remediation guidance;
      `catalog stack` always refreshes.
- [ ] Preserve auth separation:
      registry/admin operations use catalog API auth; CloudFormation,
      CloudWatch, and ECS operations use the ambient AWS credential chain.
- [ ] Update tests to assert behavior, not historical error text:
      missing cache should auto-discover where expected, and cache-only
      commands should be explicit exceptions.

Guardrails
----------

- Do not introduce a new persistent config format.
- Do not mix Quilt API keys into AWS credential resolution.
- Do not make `logs` perform ECS mutations; log-level changes belong under
  `ecs`.
- Keep each CLI command thin: parse args, call shared context/resource helpers,
  perform the operation, render output.

Suggested Order
---------------

1. Add stack payload requirement/accessor helpers with unit tests.
2. Migrate `ecs logs` and `catalog stack` first because they expose the current
   inconsistency.
3. Migrate `ecs shell` list/default selection.
4. Migrate `run-migration` and `quiltx.ecs` helpers.
5. Remove duplicate missing-cache messages and payload parsing branches.
