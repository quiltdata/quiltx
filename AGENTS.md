# quiltx developer notes

## Developer Setup

- Setup: `./poe setup` (install deps + hooks)
- Run tests: `./poe test` (unit) or `./poe test-all` (full suite)
- Run from repo: `./poe run <tool>` (e.g., `./poe run config --help`)

## Tools

### Bucket Tool (`quiltx bucket`)

`quiltx bucket add --no-preflight` skips local S3/SNS bucket-owner setup and
registers through GraphQL only, letting the catalog stack probe with its own
IAM. The same mode is available for ACL reconciliation with
`quiltx catalog acl --no-preflight` or `QUILTX_NO_PREFLIGHT=1`.

Post-add verification runs on both add paths (`--no-test` opts out) and reports
registration, live access, and index wiring separately:

- Live access is a server-side probe: `quiltx.bucket.probe_bucket_access` reads
  the bucket's full catalog configuration and resubmits it unchanged, so the
  registry re-validates S3/SNS with the stack's own identity. Configuration is
  never rewritten; a catalog that cannot answer yields `status "unavailable"`
  and callers fall back to the index probe.
- Index wiring is a warning once live access is verified (indexing lags, and
  empty buckets never index); `--require-index` makes it fatal.
- `quiltx bucket test BUCKET --pre-registration [--profile P]` checks a
  cross-account grant before registration using control-account credentials and
  reports the probing principal.

Cross-account grants accumulate. `quiltx.bucket.PRINCIPAL_ACCUMULATING_SIDS`
lists the two statements whose `Principal.AWS` entries are unioned instead of
replaced (`QuiltCrossAccountAccess` on the bucket policy and
`QuiltCrossAccountSNSAccess` on the topic policy). Everything else, including
the `QuiltBucketNotifications` publish statement that doubles as the topic
ownership marker, keeps replace-by-Sid semantics. Existing principals retain
their document order and requested ones are appended, so a repeat run is a
no-op. `quiltx bucket revoke` is the only path that removes a principal; it
rewrites just those two statements, deletes the bucket policy when no statement
would remain, and leaves notifications and the SNS topic alone.

### ECS Tool (`quiltx ecs`)

Provides catalog ECS operations:

- `quiltx ecs logs` displays/tails CloudWatch logs and can set/reset ECS log level.
- `quiltx ecs status` shows or waits for service rollout status.
- `quiltx ecs shell` opens an interactive shell in running ECS tasks. Requires AWS Session Manager plugin (CLI will prompt with install instructions).
- `quiltx ecs run-migration` re-runs the registry migration task.

### Stack API (`quiltx.stack`)

Python module for discovering CloudFormation stacks and working with cached stack data. See module docstrings for API details.

### Stack ACL (`quiltx stack acl`)

Uses the flat `policies:` / `roles:` YAML format documented in
[`stack-acl.example.yaml`](stack-acl.example.yaml).
The old `bucket_policies:` / `roles:` / `sso:` format is no longer supported.

`config.unmanaged: true` references an existing IAM-backed role by name. Such
roles are never created, updated, or deleted; they only stay addressable from
`users:`, SSO selectors, and `config.default_role`. `--yaml` always emits an
entry for every unmanaged role it finds so captures replay cleanly.

`quiltx.acl.analyze_user_downgrades` compares each user's effective access
(roles, admin, composed bucket permissions) before and after a diff.
`--dry-run` prints a `!! DOWNGRADE` block per affected user; `--yaml` re-parses
its own output, diffs it against the captured state, and reports risks both in
the `# not captured:` notes and on stderr. Opaque (unmanaged) roles and roles
kept under a changed SSO selector are reported as undetermined; SSO and
default-role effects apply to SSO-only users, and only when the SSO document
itself changes.

### Config API (`quiltx.config`)

Functions for catalog configuration and credentials. Use `from quiltx.config import` for programmatic access.

## Publishing Releases

1. Update `version` in [pyproject.toml](pyproject.toml) and [CHANGELOG.md](CHANGELOG.md)
2. Merge to `main`

On each push to `main`, [.github/workflows/publish.yml](.github/workflows/publish.yml)
checks whether a `v$VERSION` tag already exists. If not, it builds, tags, creates the
GitHub release, and publishes to PyPI. If the tag already exists, the run is a no-op —
so only version bumps trigger a release.

`./poe tag` remains available for manual/local tagging if ever needed.
