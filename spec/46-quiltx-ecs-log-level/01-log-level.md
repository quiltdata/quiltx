---
title: "Log level for ECS tasks"
branch: "46-quiltx-ecs-log-level"
issue: "https://github.com/quiltdata/quiltx/issues/46"
---

Issue copied from GitHub: https://github.com/quiltdata/quiltx/issues/46

## Goal

Add a new `quiltx ecs logs`  subcommand to enable/disable logging as a one-liner.

## Context

Currently, adjusting ECS log levels (e.g., `QUILT_LOG_LEVEL=DEBUG`) requires manual steps:
1. Describe the ECS task definition
2. Create a new task definition revision
3. Update the container environment variable
4. Update the ECS service to use the new revision
5. Force a new deployment

This should be automated into a single command.

## Proposed Solution

Implement a `quiltx ecs` subcommand with the following capabilities:

- easily sets and resets log levels
- defaults to debug
- automatically detects stack and containers

Or similar interface that:
- Fetches the current ECS task definition for the registry service
- Creates a new task definition revision with the updated log level
- Updates the service to use the new revision
- Forces a new deployment

## Acceptance Criteria

- [ ] `quiltx ecs` command works as a one-liner
- [ ] Supports enabling/disabling DEBUG logging (with options for other levels)
- [ ] Uses the usual --catalog and auth options
- [ ] Provides clear feedback on success/failure
- [ ] Handles edge cases (missing service, permission errors, etc.)

Original issue metadata
-----------------------

- Repository: quiltdata/quiltx
- Branch: 46-quiltx-ecs-log-level
- Issue: #46
