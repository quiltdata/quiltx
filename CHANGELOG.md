<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Replace quiltx's process-wide monkey-patch of
  `quilt3.session.get_registry_url` with quilt3's supported context-local
  registry resolver, and bind API keys explicitly to the registry advertised
  by each catalog. The obsolete quiltx synchronization lock and URL
  `ContextVar` are removed; quilt3 now owns URL isolation, key scoping, and
  session synchronization. Require `quilt3>=8.1.0a2,<9` for these APIs.

## [0.19.0] - 2026-08-20

### Changed

- Pin `quilt3>=8.0.0,<9` and raise `requires-python` to `>=3.10`. quiltx
  previously declared `quilt3>=7.3.0` with no upper bound while its lockfile
  resolved 7.3.0, so `pipx install quiltx` in deployment CI could resolve a
  quilt3 release the project had never tested against — quilt3 8.0.0 shipped
  2026-08-04 and dropped Python 3.9. The lockfile now resolves quilt3 8.0.0,
  and the full suite (473 tests) passes against it on Python 3.10 and 3.14.
- CI now runs the test suite across Python 3.10-3.14 instead of 3.14 alone, so
  the supported range is verified rather than assumed. Linting and type
  checking run once in a separate job.

## [0.18.4] - 2026-08-19

### Fixed

- `quiltx catalog acl --yaml` now preserves registered buckets that have no
  explicit managed-policy association
  ([#97](https://github.com/quiltdata/quiltx/issues/97)). Otherwise-unrepresented
  buckets are emitted as registration-only references on the built-in
  `ReadQuiltBucket` and `ReadWriteQuiltBucket` roles, while buckets already
  represented by managed policies or managed-role inline policies are not
  duplicated. Captures remain parseable and replayable: a compatible target
  plans only missing bucket registration, never policy changes or mutations to
  the IAM-backed built-in roles. Custom unmanaged roles still reject
  `buckets.*`, and `config.policies` remains invalid on every unmanaged role.

## [0.18.3] - 2026-08-17

### Added

- ACL configs can reference the catalog's built-in unmanaged roles with
  `config.unmanaged: true`, and `quiltx catalog acl --yaml` always emits an
  entry for every unmanaged role it finds — including the two built-in defaults
  — even when no user or SSO selector references them
  ([#88](https://github.com/quiltdata/quiltx/issues/88)). The roles are
  discovered and referenced by name only: they stay addressable from `users:`,
  `sso.<claim>` selectors, and `config.default_role`, while reapplying the
  generated ACL never recreates, converts, updates, or deletes them. Declaring
  a role unmanaged also protects a same-named managed role from deletion, and
  `config.policies`/`buckets.*` are rejected on unmanaged entries because those
  grants live in IAM. Users, SSO mappings, and the settings default role that
  point at an unmanaged role now round-trip instead of landing in
  `# not captured`.
- `quiltx catalog acl` warns when an export or reconciliation would reduce an
  existing user's effective access
  ([#89](https://github.com/quiltdata/quiltx/issues/89)). Access is composed
  role -> policy -> bucket permission, so `--dry-run` prints a per-user
  `!! DOWNGRADE` block with before/after primary role, extra roles, admin
  status, and lost permissions, covering reductions caused indirectly by a
  narrowed policy, a deleted role, a replaced SSO mapping, or a changed default
  role. `--yaml` re-parses its own output and diffs it against the captured
  state, listing affected users in the `# not captured:` notes and repeating
  them on stderr so the warning survives `--yaml > file`. Neutral role renames
  and privilege increases are not flagged; permissions granted by an
  IAM-backed unmanaged role, and roles that survive under a changed SSO
  selector, are reported as undetermined rather than guessed, since the
  registry exposes neither IAM grants nor a user's IdP claims.
  New API: `quiltx.acl.analyze_user_downgrades`,
  `current_state_as_acl_yaml_with_warnings`, `export_downgrade_warnings`,
  `parse_acl_config_text`, `UserAccess`, and `UserDowngrade`.

## [0.18.2] - 2026-08-17

### Added

- `quiltx bucket test` and post-add verification now run a server-side live
  access probe ([#87](https://github.com/quiltdata/quiltx/issues/87)). The
  catalog re-validates the bucket with the stack's own service identity, so a
  valid empty bucket passes, revoked access fails even when stale search-index
  entries remain, and failures name the failed capability (bucket metadata,
  S3 read, notification configuration, or SNS topic) plus the control account
  and stack principal. Registration, live access, and index wiring are reported
  as three separate checks. A catalog that cannot answer the probe is reported
  as skipped, and verification falls back to the index probe. The probe
  resubmits the bucket's existing catalog configuration unchanged to trigger
  re-validation; `QUILTX_NO_LIVE_PROBE=1` skips it.
- `quiltx bucket test --pre-registration` checks a cross-account grant before
  any catalog registration exists ([#92](https://github.com/quiltdata/quiltx/issues/92)):
  bucket reachable, `GetBucketNotification` readable, and the SNS topic policy
  granting `Subscribe`/`GetTopicAttributes`. It runs from the control account
  (`--profile`), reports the principal used, and fails when that principal is
  not in the catalog's control account, so a wrong-account grant surfaces at
  handoff instead of as an opaque `AccessDenied` inside `catalog acl`. Topic
  policies are read conservatively: an explicit `Deny` overrides an allow, and a
  condition-bearing allow is reported as conditional rather than granted.
- `quiltx bucket test --require-index` and `quiltx bucket add --require-index`
  treat an empty search index as a failure. By default an empty index is a
  warning once live access is verified, since indexing lags registration and
  empty buckets never index.

### Fixed

- `quiltx bucket add --no-preflight` now verifies after registering
  ([#92](https://github.com/quiltdata/quiltx/issues/92)). The documented
  cross-account flow previously exited 0 without any check, reporting success
  for a bucket that was registered but unreadable and unindexed. `--no-test` is
  now the opt-out on that path too, instead of being silently a no-op, and an
  already-registered bucket is verified rather than skipped.
- `quiltx bucket test` reports the Quilt control account and stack principal on
  failure instead of `unknown`, which is precisely the diagnostic needed when a
  grant was issued to the wrong account
  ([#92](https://github.com/quiltdata/quiltx/issues/92)).

## [0.18.1] - 2026-08-17

### Fixed

- `quiltx bucket prepare --catalog DNS` no longer reports the ambient AWS
  account as the Quilt control account ([#91](https://github.com/quiltdata/quiltx/issues/91)).
  Without cached stack metadata, the account is now derived from credentials
  minted by the catalog's own registry; if the catalog will not mint them,
  the command fails and asks for an explicit `--control-account-id` or
  `--principal` instead of emitting a plausible wrong principal. The message
  names the credential source it actually used.
- Bucket access probes resolve the bucket's region before testing access, so a
  bucket outside the profile's default region is no longer reported as
  unreachable (`GetBucketLocation` answers `AccessDenied` across regions).
  `bucket prepare`, `bucket add`, and `catalog acl` can now preflight
  out-of-region buckets.

## [0.18.0] - 2026-08-12

### Added

- `quiltx bucket prepare` configures cross-account S3 access, SNS policy, and safe object notifications using bucket-owner AWS credentials only, with exact dry-run documents and a minimal JSON handoff for a separate catalog operator.
- `quiltx bucket prepare --catalog DNS` derives the control account ID from cached stack metadata or, failing that, by logging in as a regular catalog user (no admin role) and reading the account behind the catalog-minted credentials.

### Changed

- `quiltx bucket add` and ACL bucket reconciliation now run through the same preparation planner/applicator as `bucket prepare`, gaining its conflict detection, stale-destination validation (SNS, SQS, and Lambda), and per-write drift rechecks; `--force` re-registration only removes the catalog row after AWS preparation succeeds.

## [0.17.3] - 2026-08-12

### Added

- `quiltx catalog acl --yaml --omit-default-users` emits a concise declarative ACL export by excluding non-admin users assigned only to the catalog default role.

## [0.17.2] - 2026-08-11

### Fixed

- `quiltx catalog acl` sets the default role by role **id** instead of name: passing a name made quilt3 query `role(id: <name>)`, which UUID-keyed registries answer with an Internal Server Error, failing every apply that reconciled the default role.
- Settings-level default-role reconciliation no longer fails on catalogs where the registry locks that setting (SSO config present and password signup disabled, e.g. nightly): when the SSO config itself names the same default role, the conflict is reported as governed-by-SSO-config and the apply succeeds; a conflicting SSO config still warns.

## [0.17.1] - 2026-08-11

### Added

- `quiltx catalog login` accepts passwords through `QUILTX_PASSWORD` or `--password-stdin`, and `--no-store` prints a minted key without accessing persistent credential storage for secure CI use.

## [0.17.0] - 2026-08-10

### Added

- Formal release of declarative catalog ACL management, including managed policies and roles, SSO mappings, user assignments, default-role reconciliation, and replayable YAML export.

## [0.16.10] - 2026-08-10

### Fixed

- `quiltx catalog acl` now captures and reconciles the settings-level default role, including selector-less roles used by password-auth stacks, and rejects SSO selectors without a declared default role.

## [0.16.9] - 2026-08-10

### Added

- `quiltx catalog acl --yaml` exports current managed ACL state as replayable flat YAML, including reusable policies, static roles, representable SSO selectors, and user role assignments.

## [0.16.8] - 2026-08-10

### Added

- Declarative reconciliation of existing users' primary role, ordered extra roles, and optional administrator status through a top-level `users:` mapping.

## [0.16.7] - 2026-08-10

### Added

- Policies may set `config.synthesize: false` to remain reusable managed policies without contributing to the cumulative role ladder or SSO mappings.

## [0.16.6] - 2026-08-10

### Added

- Top-level static roles may omit SSO selectors while retaining their managed role and policy grants without emitting SSO mappings.

## [0.16.5] - 2026-08-10

### Fixed

- ACL policy updates and deletes now resolve titles from the fetched policy list and pass UUIDs to quilt3, avoiding registry 500s from `policy(id:)` queries with policy titles.

## [0.16.4] - 2026-08-10

### Added

- `quiltx catalog acl` current-state output now includes users and role assignments, and `--json` exports the complete ACL state for automation and migration.

## [0.16.3] - 2026-08-10

### Added

- Policy entries in `quiltx catalog acl` accept a `name` field that gives the cumulative synthesized role a short display name without creating duplicate roles or SSO mappings.

## [0.16.2] - 2026-08-10

### Fixed

- `quiltx catalog acl` preserves the registry-managed `Canary` role and `CanaryBucketAccess` policy during reconciliation, preventing disruption to the `_canary` service user.

## [0.16.1] - 2026-05-14

### Added

- `quiltx bucket add --no-preflight` and `quiltx catalog acl --no-preflight` register buckets through GraphQL only, skipping local S3/SNS bucket-owner setup and letting the catalog stack probe with its own IAM. `QUILTX_NO_PREFLIGHT=1` enables the same mode for scripted runs.
- `quiltx catalog acl --no-preflight --dry-run` now lists the local AWS steps that would be skipped (per `spec/7-no-preflight.md` §140).

### Changed

- `quiltx bucket add --no-preflight` never prompts for confirmation; `--yes` help, `--no-preflight` help, and the README example document `--yes` as unnecessary in that mode (spec §144).

### Fixed

- `quiltx bucket add --no-preflight` now has CLI-boundary test coverage asserting that `BucketAddError` is rendered to stderr with a non-zero exit code.

## [0.16.0] - 2026-05-08

### Added

- `quiltx catalog api-key` prints the stored `qk_...` API key for a catalog, with `--new` to mint, store, and print a replacement. Supports browser-based login or `--username`/`--password` U/P bootstrap, plus `--insecure` for localhost testing.
- `quiltx catalog login` mints and stores a catalog API key during the auth flow so downstream tools can reuse it without re-authenticating.

## [0.15.0] - 2026-05-07

### Added

- `quiltx ecs logs --set-level LEVEL` updates `QUILT_LOG_LEVEL` on the registry service via a new task definition revision and forced deployment; `--reset-level` removes the override. Auto-discovers stack, cluster, service, and container.
- `quiltx ecs status` shows or waits for ECS service rollout status (primary deployment, running/desired counts, recent events). Supports `--wait` with timeout.

### Changed

- Moved log viewing under the `ecs` group: `quiltx logs` is now `quiltx ecs logs`. The old top-level `logs` command has been removed.
- Centralized stack/context resolution in `quiltx.stack`: catalog lookup, stack discovery, region selection, and ECS resource extraction now follow one shared path across `catalog`, `ecs`, and `bucket` commands. Read-only commands auto-discover the stack payload; mutating commands auto-discover then fail with explicit remediation when required fields are missing.
- `ecs logs` truncation floor raised to 160 characters so long log lines remain readable.

## [0.14.2] - 2026-05-07

### Added

- `quiltx catalog acl` accepts arbitrary `sso.<claim>` selectors, not only `sso.groups`, and emits SSO JSON Schema mappings for scalar or array-valued custom claims.

### Fixed

- `quiltx catalog acl` uses role and policy IDs from fetched state when updating or deleting existing resources, avoiding quilt3 name-as-ID lookup failures that surfaced as opaque `Internal Server Error` GraphQL errors.
- `quiltx catalog acl` now detaches users, SSO mappings, policy associations, and policy role associations before deleting roles or policies, allowing stale managed roles and inline policies to be removed cleanly.
- GraphQL error formatting no longer repeats identical wrapper and nested messages such as `Internal Server Error: Internal Server Error`.

## [0.14.1] - 2026-05-07

### Fixed

- `quiltx catalog acl` actually dedupes `(bucket, level)` now: `_permissions_for_buckets` drops READ when the bucket is also in `read_write`. Previously emitted both rows and tripped the registry's composite PK on `RolePolicyBucketPermission(role_policy_id, bucket_name)` as an opaque 500 from `policyCreateManaged` / `policyUpdateManaged`.
- `quiltx catalog acl` skips the SSO update (with a clear warning) when pruning orphaned roles would drop `default_role`. Previously the pruned payload was sent without `default_role` and the registry rejected it with `InvalidInput: config.default_role: field required` — `SsoConfig.default_role` is a required pydantic field.
- `quiltx catalog acl` policy create / update / delete warnings now refetch state and append `[desired: ...; server now: ...]` on `Internal Server Error`, turning opaque 500s into actionable text. Gated on 500 so validation, auth, and not-found errors skip the extra `policies.list()` round trip.

## [0.14.0] - 2026-05-07

### Added

- `quiltx catalog login` opens `<registry>/login` in the browser and prompts for a paste-back code on interactive TTYs (works with any auth backend, including SSO). `--no-browser` falls back to username/password; `--username` and `--api-key` paths are unchanged.

### Changed

- `quiltx bucket add` on already-registered buckets reapplies S3 bucket policy / SNS / cross-account principals instead of silently skipping. `--force` still removes and re-adds the catalog registration so Quilt re-subscribes SQS.
- `quiltx bucket add` errors print exception type; full traceback under `QUILTX_VERBOSE=1`.
- On opaque `Internal Server Error` from policy create / update / delete, `quiltx catalog acl` warnings now append the desired permission set and a refetch of server-side state.

### Fixed

- `quiltx catalog acl` dedupes `(bucket, level)` permissions when a bucket appears in both `buckets.read` and `buckets.read_write` (RW implies R) — previously tripped the registry's composite PK as an opaque 500 from `policyCreateManaged`.
- `quiltx catalog acl` prunes SSO mappings referencing orphaned roles when a managed-policy create fails, so surviving roles still land (previously the whole `setSsoConfig` rejected with `RolesNotFound`, wiping all SSO state). If the prune would drop `default_role`, the SSO update is skipped with a clear warning.
- `quiltx catalog acl` no longer emits `admin: false` for non-admin SSO mappings — under `union_roles` the server treats `admin` as tri-state and `false` vetoed admin grants from co-matching admin roles.
- `quiltx bucket add` no longer performs a direct S3 `b.ls()` access check (stale local creds caused false negatives).
- `is_auth_error` matches only HTTP 401 and the literal `Unauthorized` GraphQL payload, stopping false re-auth loops triggered by unrelated `GraphQLClientGraphQLMultiError` payloads (e.g. "Bucket not found", validation errors).

## [0.13.0] - 2026-05-04

This release reshapes `quiltx`'s identity and auth surface around a per-catalog model and switches the stored secret from username/password+refresh-token to a single `qk_...` API key per DNS. quiltx no longer mutates the user's global `quilt3.config()` to do its work, no longer consumes `quilt3`'s `credentials.json`/`auth.json`, and no longer relies on Quilt-minted AWS session credentials — AWS calls flow through the standard boto3 chain. Scripts that referenced the old `quiltx stack ...` surface, `--catalog-name`, or `--username`/`--password` will fail at argparse time — there are no aliases (pre-1.0).

### Added

- New `quiltx catalog` namespace:
  - `quiltx catalog default [<dns>] [--clear]` — read, set, or clear quiltx's own default catalog (stored in `user_data_path("quiltx")/config.json`, never in `quilt3.config()`). On first run with an empty userconfig, bootstraps the default from `quilt3.config()` once. When `<dns>` has no stored API key, delegates to `quiltx catalog login` so first-time set validates that the catalog is reachable.
  - `quiltx catalog login --catalog <dns> [--username U --password P | --api-key qk_...] [--key-name N] [--expires-in-days N]` — mint a long-lived `qk_...` API key from username/password (composes `/api/login` → `/api/token` → GraphQL `apiKeyCreate`) and store it in the system keyring. Surfaces the catalog's own error verbatim on SSO-only catalogs and prompts users to paste a manually-issued key via `--api-key` instead.
  - `quiltx catalog list` — list catalogs with stored credentials (DNS, username, never the secret).
  - `quiltx catalog forget <dns>` — delete keyring entry for a DNS. Idempotent. Does not touch the default catalog or stack payload cache.
  - `quiltx catalog acl` (renamed from `quiltx stack acl`).
  - `quiltx catalog stack` (renamed from `quiltx stack cfn`).
- Per-DNS credential storage backed by the system keyring (Keychain / Credential Manager / Secret Service). Storage shape is `{api_key, name?, expires_at?}`; legacy `{username, secret}` entries from earlier development snapshots are ignored on read. Linux without a keyring backend falls back to mode-0600 JSON at `user_data_path("quiltx")/credentials.json` with a loud first-run warning.
- Per-catalog auth seam: `Catalog.ensure_auth()` resolves one `qk_...` API key, then under a serialising lock binds `quilt3` to that catalog (via a one-time `ContextVar`-backed monkey-patch on `quilt3.session.get_registry_url`, no `config.yml` writes) and calls `login_with_api_key()`. Per-DNS isolation; auth-error retries re-prompt only the catalog that failed via `ensure_auth(skip_keyring=True)`.
- Universal CLI flags: `--api-key`, `--no-prompt`, `--verbose`. Verbose preflight prints a four-line `catalog/source/auth/region` block to stderr; `_probe_auth_source()` is read-only (no prompts, no writes).
- `--insecure` flag on every command that talks to a catalog. Only accepted when the catalog DNS resolves to `localhost`; any other target is refused. Switches the catalog URL from `https://` to `http://localhost`. Never persisted — must be passed on every invocation.
- `--catalog` and the positional `dns` argument to `catalog default` accept either a bare DNS name (`open.quiltdata.com`) or a full `https://` URL (`https://open.quiltdata.com/`); the URL form is normalized to DNS at the input boundary.
- Environment variables: `QUILTX_CATALOG`, `QUILTX_API_KEY`, `QUILTX_NO_PROMPT`, `QUILTX_VERBOSE`.
- Public API for embedding: `from quiltx import Catalog; Catalog.from_dns(dns, source="flag", api_key=...)`. Constructor does no I/O; admin/AWS access is lazy.
- `quiltx catalog list` renders `DNS / KEY NAME / VALID UNTIL / STATUS` columns. Status is derived from local `expires_at` only (no network probe): `ACTIVE` / `EXPIRES SOON` (<14 days) / `EXPIRED` / `UNKNOWN`.
- `Catalog.aws_session(profile=...)` returns a plain `boto3.Session` from the standard AWS SDK chain — no `quilt3` import, no Quilt-minted credentials. `cfn_client()` and `bucket._lightweight_stack_payload()` likewise use ambient AWS chain and surface a clear error if no AWS creds are available.
- `quiltx bucket add --no-prompt` requires `--yes` (or `--dry-run`); profile-fallback prompts are also suppressed in headless mode.

### Changed

- `--catalog-name` is renamed `--catalog` everywhere it appeared.
- `logs`, `ecs shell`, `ecs run-migration`, and `catalog stack` (bootstrap) now flow through the unified `@catalog_command(auth=False)` resolver.
- `quilt3` access is consolidated behind `quiltx.quilt3_facade`; runtime callers no longer import `quilt3` directly.

### Removed

- `quiltx stack` namespace and all its subcommands (replaced by `quiltx catalog`).
- `quiltx stack catalog` (the URL-setter that wrote to `quilt3.config()` — global-state mutation no longer fits the multi-catalog model).
- `quiltx.config.set_catalog_url` and `get_catalog_url` (zero callers post-multi-auth).
- `--username` / `--password` flags and `QUILTX_USERNAME` / `QUILTX_PASSWORD` env vars (replaced by `--api-key` / `QUILTX_API_KEY`).
- `quiltx/quilt_auth.py` (`acquire_refresh_token`, `validate_refresh_token`), `quilt3_facade.login_with_token`, and `quilt3_facade.default_boto3_session` — quiltx no longer mints refresh tokens or consumes Quilt-rotated AWS session credentials. AWS calls go through the standard SDK chain.
- `Catalog.boto3_session()` (replaced by `Catalog.aws_session(profile=...)`).

### Fixed

- Catalog identifier normalization rejects `http://`, custom ports, and IP literals; previously these passed silently through `get_hostname`.

## [0.11.0] - 2026-04-23

### Added

- Union-of-matches SSO role assignment: `quiltx stack acl` now always emits `union_roles: true` in the generated SSO config, so a user matching multiple mappings gets all of those roles (requires a registry that consumes the flag).
- `quiltx bucket remove` unregisters a bucket from the Quilt catalog (leaves S3 policy / SNS / notifications intact).
- `quiltx bucket add --force` re-applies the S3 bucket policy, SNS topic policy, and notification config when the bucket is already registered, and performs a remove-then-add against the catalog so Quilt re-subscribes its SQS queues to the bucket's SNS topic.

### Changed

- Renamed the canonical ACL example to `stack-acl.example.yaml` at the repo root.

### Fixed

- `quiltx stack acl` policy updates no longer silently fail: resolve the policy id from current state before calling `admin_policies.update_managed` (the title-based fallback was unreachable because `quilt3` raised 500 on non-UUID inputs), and preserve existing role attachments in the update.
- `quiltx bucket` verification prints a prominent FAILED line identifying the failing stage, probes the catalog search index to confirm SNS→SQS wiring actually landed, and no longer trips AccessDenied on bucket-metadata calls (`GetBucketLocation`, `GetBucketVersioning`, `GetBucketNotification`, `GetBucketCORS`, `GetBucketTagging` added to `QUILT_POLICY_ACTIONS`).

## [0.10.5] - 2026-04-23

### Fixed

- Publish workflow now serializes concurrent runs on `main` via a `publish` concurrency group, and tolerates a pre-existing tag gracefully (skips GitHub release + PyPI publish steps rather than failing after `uv build`).

## [0.10.4] - 2026-04-23

### Changed

- Auto-release on merge to `main` when `pyproject.toml` version is bumped. The publish workflow now triggers on push to `main`, tags `v$VERSION` if the tag is new, and publishes to PyPI. No more manual `./poe tag` step. If the version tag already exists, the run is a no-op.

## [0.9.2] - 2026-04-17

### Added

- `quiltx bucket add --principal ARN` flag to set the IAM principal(s) granted cross-account access in the bucket policy. Repeatable or comma-separated. Bare `--principal` prints guidance on choosing Quilt service role ARNs.

### Removed

- `quiltx bucket add --stack-only` flag. It restricted the bucket policy to the stack's `RegistryRoleARN`, which is the ECS task execution role — not a role Quilt uses to access data buckets. Quilt does not publish an official list of roles for the bucket policy; the documented principal is the control account root. Use `--principal ARN` if you want to narrow access yourself.

### Changed

- `quiltx bucket add` no longer requires CloudFormation access in any account: when the Quilt stack role lacks `cloudformation:DescribeStacks`, it derives `account_id` from `sts:GetCallerIdentity` on the Quilt session and reads `region` from the catalog `config.json`.

## [0.9.0] - 2026-04-17

### Added

- `quiltx bucket add --stack-only` flag to restrict the bucket policy principal to the stack's RegistryRoleARN instead of the entire control account
- Direct-ACL specification (`spec/060-stack-acl/08-direct-acl.md`) and example YAML files (`dynamic-roles.yaml`, `static-policies.yaml`)
- `quiltx stack catalog --ca-bundle PATH` and `--insecure` flags for catalogs behind corporate TLS-inspection proxies or with self-signed certificates

### Changed

- **BREAKING**: `quiltx stack acl` now only accepts the flat `policies:` / `roles:` format; the old `bucket_policies:` / `roles:` / `sso:` schema is rejected
- `quiltx stack acl` now synthesizes cumulative managed roles from policy order, generates inline managed policies for static-role bucket grants, and derives SSO mappings directly from policy and role audiences
- `quiltx stack acl` no longer prompts for a default role; `config.default_role: true` on a policy controls the emitted SSO default role
- Stack ACL docs now use `spec/060-stack-acl/simpler-stack-acl.yml` as the canonical example and explain the order-sensitive synthetic role model
- CloudFormation discovery now uses `quilt3.session.get_boto3_session()` when available, so `quiltx bucket` and stack discovery work for users who have run `quilt3 login` without needing CFN permissions on their own AWS identity
- `quiltx bucket` commands are wrapped with `@auto_login`, re-prompting for `quilt3 login` on auth errors

### Fixed

- Reject ACL config names that would collide with reserved generated inline-policy titles ending in `__inline`
- Delete stale synthesized roles in the same reconciliation pass after policy rename/reorder by deriving role deletions from the desired role set instead of the current SSO snapshot

## [0.7.1] - 2026-04-11

### Added

- Confirmation prompt for `quiltx ecs run-migration` showing stack, cluster, and task definition before execution; skip with `--yes`

## [0.7.0] - 2026-04-11

### Added

- `quiltx ecs run-migration` to re-run the registry migration ECS task for a stack using cached CloudFormation metadata
- Public `quiltx.ecs` helpers for finding the migration task definition, resolving registry service networking, launching the task, and waiting for completion
- Explicit ECS launch-failure reporting for migration reruns, including surfaced `run_task()` failure reasons
- Lake Formation troubleshooting docs for the stack ACL rollout, including the post-mortem, migration rerun spec, status tabulation, and a datasets ACL example

### Changed

- **BREAKING**: `quiltx ecs` is now a subcommand namespace; use `quiltx ecs shell` for interactive task access instead of bare `quiltx ecs`
- README now documents the split ECS CLI (`ecs shell`, `ecs run-migration`) and the `quiltx.ecs` Python API

### Fixed

- `quiltx stack acl` now always shows each apply step (`-> add bucket`, `-> create policy`, etc.) regardless of `--verbose`, so users can see which operation failed
- GraphQL error details (path, message, locations) are always shown on failure, not just in `--verbose` mode
- Bucket and policy creation failures are caught and reported immediately with context (e.g. which failed buckets a policy references), then apply continues with remaining operations
- Role creation, SSO config, and delete failures are similarly caught and reported without aborting

## [0.6.0] - 2026-04-09

### Added

- `quiltx stack acl <config.yml>` for declarative reconciliation of Quilt buckets, managed policies, managed roles, and SSO mappings from YAML
- `quiltx stack acl` (no args) dumps the current server ACL state for inspection
- `--dry-run` flag to preview ACL changes without applying them
- `--verbose` flag for detailed diff output including SSO and default-role details
- Progress output during ACL apply (bucket, policy, role, SSO steps)
- SSO create-vs-update detection: creates new SSO config or updates existing one as needed
- Default role configuration moved into SSO config for cleaner YAML semantics
- `auto_login` decorator in `quiltx.config` for automatic session refresh on auth failure
- `normalize_catalog_url()` helper in `quiltx.config`
- Public Python API: `AclConfig`, `AclDiff`, `CurrentState`, `all_buckets`, `apply_acl`, `build_sso_config`, `compute_diff`, `fetch_current_state`, `parse_acl_config`, `print_diff` exported from `quiltx`

### Changed

- Add `pyyaml` as a runtime dependency for YAML-backed ACL configuration
- Require `quilt3>=7.3.0` so `quiltx stack acl` can use the new admin policies API
- `set_catalog_url()` now normalizes the URL (adds `https://`, strips trailing slash)

## [0.5.0] - 2026-04-09

### Changed

- **BREAKING**: `quiltx stack` is now a subcommand namespace with:
  - `quiltx stack catalog` — show/set the Quilt catalog (replaces `quiltx config`)
  - `quiltx stack cfn` — discover the CloudFormation stack (replaces bare `quiltx stack`)
- **BREAKING**: `quiltx config` removed as a top-level command; use `quiltx stack catalog` instead
- `bucket add` auto-discovers CloudFormation stack when no cached metadata exists, removing the need to run `quiltx stack cfn` first

## [0.4.8] - 2026-04-06

### Changed

- Remove `s3:GetBucketNotification` and `s3:PutBucketNotification` from cross-account bucket policy (#20)

## [0.4.7] - 2026-04-06

### Fixed

- Fix publish workflow: remove `gh release create` from `poe tag` to avoid conflict with CI release step

## [0.4.5] - 2026-04-06

### Changed

- Configure Renovate for grouped major/minor+patch dependency PRs, disable Dependabot
- Hyperlink "available" to PyPI release page in release notes script

## [0.4.4] - 2026-04-06

### Changed

- `poe tag` release notes now embed actual CHANGELOG content instead of GitHub-generated PR links
- `poe tag` uses `scripts/release_notes.py` to extract notes from CHANGELOG.md
- README: use `uvx quiltx` consistently throughout, drop "Install" section

## [0.4.0] - 2026-04-03

### Added

- `bucket` tool for registering cross-account S3 buckets with Quilt:
  - `quiltx bucket add|list|test`
  - merge/update S3 bucket policy and bucket notifications
  - create or reuse SNS topics and patch topic policies for S3 publish plus Quilt
    `RegistryRoleARN` subscribe access
  - `bucket add` automatically runs the same registration/read verification as
    `bucket test` unless `--no-test` is set
  - `bucket test` verifies the bucket is registered in Quilt and readable from the
    control account
  - `--profile`, `--dry-run`, `--title`, and `--no-test` support for data-account workflows
  - Rich context tables and JSON syntax highlighting for dry-run/confirmation output

## [0.3.0] - 2026-02-01

### Added

- **Documentation and Read the Docs integration**:
  - MkDocs documentation site with Material theme
  - Read the Docs configuration for automated docs building
  - Comprehensive API reference documentation with mkdocstrings
  - User guides for CLI tools and Stack API
  - Getting started guide and contributing documentation
  - Dark mode support and enhanced navigation
- **New semantic configuration functions**:
  - `get_catalog_config()`: Get the full quilt3 catalog configuration
  - `get_catalog_url()`: Get the catalog URL from configuration
  - `get_catalog_region()`: Get the AWS region from configuration
  - `set_catalog_url()`: Set the catalog URL in quilt3 configuration

### Changed

- **BREAKING**: Removed `configured_catalog()` function
  - Replace `configured_catalog()` with `get_catalog_config()` for full config
  - Replace `configured_catalog()["navigator_url"]` with `get_catalog_url()`
  - Use `set_catalog_url()` to configure a new catalog instead of `configured_catalog(url)`
- All new functions have clear, semantic names that indicate whether they read or write
- New functions raise `ValueError` with helpful messages when catalog is not configured
- **Documentation improvements**:
  - README simplified with focus on installation and quick examples
  - AGENTS.md streamlined for developer reference
  - API reference updated to use new config function names
  - Contributing guide updated with new API exports

### Fixed

- Documentation now properly references the new config API instead of deprecated `configured_catalog()`

## [0.2.1] - 2026-02-01

### Added

- Version bump to 0.2.1 for intermediate release

## [0.2.0] - 2026-02-01

### Added

- **New `ecs` tool**: Interactive shell access to ECS tasks
  - Open interactive shells in running ECS containers using AWS Session Manager
  - Automatic Session Manager plugin detection with installation instructions
  - Smart defaults: Auto-selects RegistryService and remembers previous selections
  - Reachability checks: Test network connectivity to catalog services from ECS (`--reachability`)
  - Execute Command management: Automatically detects and enables Execute Command on services
  - Interactive prompts for cluster/service selection with `--prompt` flag
  - List mode: View available ECS clusters and services with `--list`
  - Region auto-detection from stack payload
- **New `utils` module**: General utility functions
  - `get_bucket_region()`: Get AWS region of S3 buckets
  - `normalize_url()`: Normalize URLs to canonical form
  - `get_hostname()`: Extract hostname from URLs
- **Stack payload enhancements**:
  - ECS resources now included in stack payload (`ecs_resources`)
  - Catalog configuration cached in stack payload (`catalog_config`)
  - Version tracking with `quiltx_version` field
  - New `load_stack_payload()` function for loading cached data
  - New `ensure_min_version()` function for version compatibility checks
- **Stack API improvements**:
  - New `list_ecs_resources()` function for discovering ECS clusters/services
  - Auto-detection of AWS region from catalog configuration
  - Automatic boto3 client creation when not provided

### Changed

- **Stack API simplified**: CloudFormation client now optional
  - `find_matching_stack()`: Now accepts `region` parameter and creates client automatically
  - `list_log_group_resources()`: Now accepts `region` parameter and creates client automatically
  - All stack functions can optionally accept pre-configured boto3 clients for advanced use cases
- **Code organization**:
  - Moved `configured_catalog()` to separate `quiltx.config` module
  - Created `quiltx._version` module for centralized version management
  - Reduced exports from `quiltx.__init__` to only `__version__` and `configured_catalog`
- **Developer tooling**:
  - Updated `bump_version.py` script to use `_version.py` instead of `__init__.py`

## [0.1.3] - 2026-01-09

### Changed

- **Publishing workflow improvements**:
  - Automated PyPI publishing now triggers directly on git tag pushes (no manual GitHub Release creation needed)
  - GitHub Releases are automatically created with release notes when tags are pushed
  - Build system switched from pip to uv for faster, more reliable builds
  - Distribution files (wheel and tarball) automatically attached to GitHub Releases

## [0.1.2] - 2026-01-08

### Added

- `logs` tool: Enhanced log display and filtering capabilities
  - Stream-based filtering: Filter logs by stream name with substring matching (e.g., `quiltx ecs logs registry/registry`)
  - `--wrap` flag: Option to wrap long log messages instead of truncating (auto-enabled when filtering by stream)
  - Health check coalescing: Consecutive health check log entries are automatically summarized to reduce noise
  - Default behavior now shows all log streams instead of just LogGroup
- Developer tooling improvements:
  - Enhanced `bump_version.py` script with automated git commit workflow
  - Version bumping now automatically updates `uv.lock` and commits all changes
  - Added git status validation to prevent bumping with uncommitted changes

### Changed

- `logs` tool positional arguments now filter by stream name instead of log group keys
- Health check detection improved to recognize ELB health checker and GET / requests

## [0.1.1] - 2026-01-08

### Added

- `stack` tool: Discover and cache CloudFormation stack metadata with catalog matching
  - `--catalog-name` flag for flexible catalog specification without quilt3 config
  - Summary display showing stack name, region, account, and resource counts
- `logs` tool: Retrieve and follow CloudWatch logs with dynamic display
  - Follow mode enabled by default with single-screen dynamic updates using Rich Live
  - Time-based filtering (--since, --until)
  - Color-coded log levels (ERROR=red, WARN=yellow, INFO=blue, DEBUG=dim)
  - Auto-detecting console size and stream management
- CLI improvements: Subparsers showing all available tools with descriptions
- Developer tooling enhancements:
  - Pre-commit hooks with Black and mypy
  - CI lint validation workflow
  - Poe task sequences for automated dependency management (`./poe setup`, `./poe sync`)
  - Simplified developer documentation in AGENTS.md

## [0.1.0] - 2026-01-08

Initial release of quiltx - a unified toolkit for Quilt workflows.

### Added

- Unified CLI with single `quiltx` entry point
- Built-in tool: `config` for configuring Quilt catalogs using `configured_catalog` API
- Automatic tool discovery system (no explicit registry needed)
- Shared utilities library with `configured_catalog` helper
- Comprehensive tests for CLI and config tool
