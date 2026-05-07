---
title: "Compare `ecs` vs `logs` command for setting debug level"
branch: "46-quiltx-ecs-log-level"
---

Goal
----

Assess whether to implement the log-level one-liner as an `ecs` subcommand (e.g. `quiltx ecs logs`) or extend the existing `logs` command, and whether a refactor is needed.

Background
----------

- There are two relevant CLI surface areas:
  - the `ecs` toolset under `quiltx tools ecs` (operations that manipulate ECS resources: task definitions, services, deployments)
  - the `logs` command (typically used to fetch/stream logs from running containers)

Considerations
--------------

- Purpose and semantics
  - `ecs`: manages infrastructure and deployments (task defs, services). Changing a container environment like `QUILT_LOG_LEVEL` fits the `ecs` domain because it requires creating a new task definition revision and updating the service.
  - `logs`: read-only by nature; users expect to view/stream logs. Extending `logs` to perform deployments violates least surprise.

- Required permissions and operations
  - `ecs` already requires IAM permissions for DescribeTaskDefinition, RegisterTaskDefinition, UpdateService, and forcing deployments. Implementing log-level changes here is a natural fit.
  - `logs` currently needs only read/logs access; adding write operations would increase permission scope unexpectedly.

- UX and discoverability
  - Users looking to change runtime log level will likely expect an `ecs` or `deploy` style command, not `logs`.
  - A subcommand of `ecs` such as `quiltx ecs logs --level DEBUG` or `quiltx ecs set-log-level DEBUG` is discoverable and groups related opts (`--catalog`, `--stack`, auth flags).

- Complexity & code layout
  - `ecs` codepaths already handle task definition manipulation; reusing that code is simpler than migrating heavy operational logic into `logs`.
  - Minimal refactor: factor out a small helper that: finds target service, produces new task def with modified env, registers revision, and updates service. Place helper in `quiltx/ecs.py` or `quiltx/tools/ecs/` so both `ecs` and other callers can use it.

- Backwards compatibility & safety
  - Implement as `ecs` subcommand by default; keep `logs` read-only.
  - Provide a `--dry-run` that prints the new task definition and the API calls it would make.
  - Provide `--confirm` or `--yes` to do live changes.

Recommendation
--------------

- Implement the one-liner as an `ecs` subcommand: `quiltx ecs set-log-level|logs --level DEBUG [--service SERVICE] [--container NAME] [--dry-run]`.
- Keep `logs` focused on reading logs.
- Refactor suggestion: extract a reusable helper `update_task_log_level(service, container, level, dry_run=False)` into `quiltx/ecs.py` or `quiltx/tools/ecs/stack.py` so unit tests can exercise behavior and the CLI command stays thin.

Acceptance / Next Steps
----------------------

- Add CLI spec: new `ecs` subcommand and flags (usage examples).
- Implement helper in `quiltx/ecs.py` and unit tests under `tests/`.
- Wire CLI entry in `quiltx/cli.py` or corresponding `tools/ecs` command.
- Add integration test that performs a `--dry-run` and validates printed API calls.
