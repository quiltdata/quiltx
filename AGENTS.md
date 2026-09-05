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

`config.default_policy: true` on a policy composes it into every managed role's
`policy_titles` — last, in declaration order, deduped. It is a floor, not a
fallback: `config.default_role` fires only when a user's SSO claims matched no
mapping, so matching a narrow selector costs that user the general grant unless
every narrow role repeats it. Composing at the policy layer avoids injecting a
role into everyone's set, which would change which role each user lands on and
clutter the catalog's role switcher for all of them. `_build_desired_acl_state`
appends the titles to
`role_updates` after the ladder is built, so `cumulative_policy_titles` — and
therefore every `_synthesized_role_name` — is untouched; `_SynthesizedRole` and
`_ResolvedStaticRole` carry the composed list so `_print_verbose_state` shows
what gets applied, while `source_policies` stays the ladder. The flag requires
`config.synthesize: false`, because a rung's `sso.<claim>` selector names an
audience that a floor contradicts. Unmanaged roles get no default policy (quiltx
never edits their IAM) and that combination appends a **notice** naming both, on
`_DesiredAclState.notices` -> `diff.notices`, never `warnings`. The note says what
the two flags together mean; nothing failed. `_run` returns 1 on a non-empty
`diff.warnings`, and this is the shape `stack-acl.example.yaml` documents, so
routing it as a warning failed every `--yes` apply of a valid file that had work
to do (a no-op re-run escaped through the `not diff.has_changes()` early return).
`_DesiredAclState.notices` mirrors `warnings` and `compute_diff` extends the
matching `AclDiff` channel from each. The `_resolve_policy_admin_vote` warning is
the same routing class but stays a warning on purpose: an explicit
`config.is_admin: false` vetoing a `true` is two contradictory statements in the
file, not a note about what one statement means. `--yaml` never re-emits the
default-policy flag: each captured role already lists the policy in its composed
`config.policies`, which replays to the same state.

Because a default policy is a dependency of *every* managed role,
`AclDiff.default_policy_titles` (a `frozenset[str]`, threaded from `compute_diff`
like `no_preflight_buckets` and excluded from `has_changes()`) lets `apply_acl`
tell that case apart from an ordinary missing policy. `apply_acl` checks it
between the policy phase and the role phase and `return warnings` there if any
title is absent from `known_policies`: no role create, update or delete, no
default-role update, no user role assignment, no SSO update, no policy delete.
The check has to precede the role loops rather than diagnose them afterwards,
because the delete phases run *after* the role loops — so the old behaviour
skipped every role create and then deleted the roles and policies the file drops,
removing working access with nothing able to replace it (#110). What is left is a
clean partial apply: the policies that landed, and nothing else.
`print_default_policy_failures` names the policy in a `!! DEFAULT POLICY MISSING`
block and `default_policy_failure_message` adds the same sentence to `warnings`.
The `default_policy_titles` branches inside the two `KeyError` handlers are gone:
after the gate a `KeyError` can only name a non-default policy, so they were dead
code whose presence implied the cascade still happened. Ordinary missing policies
keep the per-role `unknown policy` skip.

Each `users:` key is resolved against the server by exact `user.name` first,
then by a unique case-insensitive `user.email` match. `user.name` is
email-shaped for SSO self-registrations (the registry derives `email[:64]`) and
handle-shaped for admin-created accounts, so one file mixes both.
`_resolve_configured_user` returns a `_ResolvedUser(user, collision)`: precedence
decides, and a key that also happens to be a *different* account's email still
resolves to the account it names, with the clash reported as a `diff.warnings`
entry naming the key, the account it resolved to, and the other one. Refusing
that combination would reject `--yaml`'s own output, which keys every entry by
`user.name`, on any catalog holding an SSO self-registration named as another
account's email — and the error asked for the username the capture already used.
Only a key that names no account and is the email of two or more raises
`ValueError`: nothing there decides between them. Two keys resolving to *one*
account also raises, because `_apply_user_updates` walks the updates in order
with `append=False`, so the later entry would silently replace the earlier one. A
key matching nothing stays a `diff.notices` entry. Everything downstream — the
SDK call, downgrade analysis, verbose output — uses the resolved server username,
and `AclDiff.resolved_user_names` maps key -> username for reporting.

Both `ValueError` cases abort with nothing written, because `_run` calls
`compute_diff` before `apply_acl` and does only read-only work in between. That
ordering is the contract, so it is pinned at the CLI level and not only around
`compute_diff` (#112): the tests run `--yes --no-preflight
--create-and-email-users` against a config with a bucket to register and a role to
create, and assert exit 1 with an empty recorder wired to every admin mutation. A
reconciled fixture would pass whether the abort came before or after `apply_acl`.

`--create-and-email-users` is the only path that creates accounts, and it is
CLI-only by design: `Users.Create` mails a welcome plus password-reset link with
no suppress flag, so a config key would make the first apply the irreversible
one. It is driven by `sso.email`, never by `users:` — that selector is already a
roster of individuals keyed by a field that cannot be a handle, and the role is
implied by the nesting, so creation and the SSO mapping cannot diverge (a
`users:` role would be replaced at first login anyway, since every login
recomputes the set). `sso.hd`/`sso.groups` name no individual and contribute
nobody.

`USERNAME_PATTERN` (`^[a-z][a-z0-9_]*$`) is the registry's grammar for an
*admin-supplied* username; the registry derives `email[:USERNAME_MAX_LENGTH]`
itself only when `name` is omitted, and holds that derivation to no pattern —
which is why one catalog carries both shapes (the same two-shape fact `users:`
key resolution is built on). quiltx cannot take the deriving path:
`UserInput.name` is `str`, not `Optional[str]`, and `quilt3.admin.users.create`
requires it, so every account quiltx creates carries a name quiltx chose.
`derive_username` supplies it by folding every character outside `[a-z0-9_]` to
`_`, prefixing `USERNAME_FALLBACK_PREFIX` when the result does not start with a
letter, and truncating to `USERNAME_MAX_LENGTH`. The result always satisfies
`USERNAME_PATTERN`, which is why `plan_user_creations` no longer pre-validates
it; that invariant is pinned by a parametrized test over empty, blank,
leading-digit, leading-underscore, punctuation-only, non-ASCII and over-length
inputs rather than by a branch that cannot fire.

The **whole address** is folded, domain included. A local-part handle maps
`alice@example.com` and `alice@contractor.example` to one name, and only one
account can hold it, so that collision costs one of two people their account.
First SSO login reconciles against the pre-created account **by email**, so the
handle is an administrative label (admin UI, `--yaml` captures) and not the
identity — this is the fact that makes pre-creation safe at all, and the reason
the mapping does not need to reproduce what the registry would have derived.

Folding is not injective: `.` and `+` both become `_`, and truncation merges any
two addresses agreeing on their first 64 folded characters. So the handle is
checked against server usernames *and* against the rest of the roster (two
passes, `claimants`, so the outcome does not depend on the order the file is
written in), and any clash refuses those addresses. No disambiguating suffix: it
would make somebody's username depend on what else happened to be in the file.

`compute_diff` consults the same helper for an unresolved `users:` key (#119):
candidates mean a warning naming them via `_quote_user_identities`, none keeps the
old nonfatal notice, so only the rename case is fatal and a captured entry for a
deleted account still does not fail a clean run. The `users:` message offers
rekeying as well as `set_email`, because a key can be rewritten and a roster
address cannot. Note `_run`'s no-changes early return is `return 1 if
diff.warnings else 0`: without that, a warning on an otherwise-reconciled config
printed and then exited 0, which is exactly the #119 case (the pin is the only
thing naming the person, so there is nothing else to apply).

Existence is not identity. quiltx never calls `quilt3.admin.users.set_email`, so
an address no account holds may be a person who already has one under their old
address — which is *why* an operator edits a roster. Neither older guard catches
it: the duplicate-account notice needs two accounts sharing one email, and the
handle check compares folded addresses, so `robbyqbutler@protonmail.com`,
`robbyqbutler@pm.me` and an account named `robbyqbutler` are three distinct
strings. `_accounts_sharing_a_local_part` matches the roster address's local part
against each account's username *and* the local part of its email (so an
email-shaped `user.name` is covered), and a hit is a `warnings` entry naming both
records with no creation. It runs in the first pass, before handle assignment:
identity precedes naming, and an address refused here never competes for a handle
it was not going to get. This treats `alice@example.com` and
`alice@partner.example` as *possibly* one person while `derive_username` treats
them as two — not a contradiction, since one refuses to silently merge two people
and the other refuses to silently split one, and both only report.

`sso_email_roster` walks `_DesiredAclState.sso_mappings`, so ladder rungs and
static roles (including unmanaged ones) are covered under the role names that
will exist; addresses fold case-insensitively under their first spelling.
`plan_user_creations` subtracts existing accounts via `_roster_address_is_held`,
which returns `(held, notice)`: it calls `_resolve_configured_user` and treats an
ambiguous address as held — a roster cannot be rekeyed by username, so raising
would abort an apply over an address needing no action — but reports it instead of
folding it silently into the "already have one" count. `UserCreationPlan` carries
two per-address channels because it reports two different outcomes: `warnings`
means "cannot be created and needs a human" (a missing role, a suspected rename,
a handle another account or another roster address holds) and `notices` means
"needs nothing done, worth reporting". Only `warnings` reach
`_unmakeable_accounts` and the exit-1 path; an ambiguous held address is already
in `existing`, so counting it as uncreatable both named one address twice and
failed a run in which nothing went wrong. `_print_user_creation_notices` prints
the notices in both readers, since only `warnings` travel back to `_run`.
Resolution order is username then unique email, the same as a `users:` key, but
for a roster it is nearly always the email index that hits: `derive_username`
folds rather than copies, so a quiltx-created account is not named after its own
address, and an SSO self-registration is only until `USERNAME_MAX_LENGTH` cuts it
off. Multi-role: last declaration is active, earlier ones are extra roles,
matching `union_roles: true` and the last-matching first-login pick.

An address is only created when every role it names exists, and
`include_planned_roles` is what "exists" means. The dry-run reader passes `True`
and gets the set `compute_diff` uses for `users:` entries — managed roles the file
declares plus unmanaged roles the server already holds — because nothing has been
applied yet, so a fresh catalog would otherwise flag every address.
`_create_and_email_users` must **not** pass it, and the parameter defaults to
`False` for that reason: it runs after `apply_acl` against a refreshed state, and
a managed role whose create *failed* is still in `state.role_updates`, so trusting
the plan there sends a creation naming a role the registry does not have. The
default is the strict one because forgetting it costs a spurious dry-run warning,
while the reverse costs an irreversible creation attempt. A `config.unmanaged:
true` role absent from the server is refused either way with a `warnings` entry
naming the address and the role, since quiltx never creates one. An *existing*
unmanaged role is creatable
into on purpose: its selector grants it at first login anyway, so pre-creating
changes nothing about who holds it. The permissions are IAM-backed, so the
downgrade analysis reports that account's access as undetermined.

Nothing about creation touches `AclDiff`, so `has_changes()` is unchanged; `_run`
instead skips its no-changes early return when the flag is set, and calls
`_create_and_email_users` after `apply_acl` *and* after the drift reset/reapply
pass, because that pass is what puts the last roles in place and refreshes
`post_current`. The plan is printed before the prompt (`_confirm_create_and_email`,
skipped by `--yes`), the count cap is `MAX_CREATED_USERS_DEFAULT` with
`--max-created-users N` as the override (its argparse default is `None`, so the
"requires `--create-and-email-users`" check tests whether the flag was supplied
rather than whether its value differs from the cap). A refusal or a decline
creates nobody; a failed create costs only that address. All three are warnings
on the CLI's existing exit-1 path. Declining the *apply* prompt returns before
the creation block, so it too creates nobody.

The optional top-level `buckets:` block carries per-bucket registration
options; `BUCKET_ENTRY_KEYS` holds the only field, `config.no_preflight`. A key
counts as a bucket reference in `all_buckets`, so a bucket registers by
declaration alone. `compute_diff` copies the flagged names to
`AclDiff.no_preflight_buckets` (never part of `has_changes()`) because
`apply_acl` gets the diff and not the config; the effective mode per bucket is
the global flag OR that set, and the missing-control-account error is raised
only for the buckets that still need preflight. `_print_no_preflight_notice` names
each such bucket and the source that put it in that mode on a real apply as well
as a dry run, so a `--yes` CI log records which buckets skipped local AWS
verification. The global CLI flag remains an
override for every bucket. `--yaml` cannot capture the block — the registry
records no registration mode — so replaying a capture against a catalog that has
yet to register a pre-prepared bucket needs the flag re-added by hand or a
global `--no-preflight`; that is documented on
`current_state_as_acl_yaml_with_warnings` rather than as a `# not captured:`
note, since a capture with buckets loses nothing by itself.

A bucket that does not register is loud. `apply_acl` still continues (partial
progress is deliberate) and still appends `Bucket '<name>' was not registered:
<reason>` per bucket, but it also prints a `!! BUCKET REGISTRATION FAILED` block
naming each bucket and reason via `print_bucket_registration_failures`. The CLI
then compares `diff.buckets_to_add` against the post-apply server state, so a
bucket the catalog still does not hold is reported and exits 1 even when the add
returned cleanly, and the final line names unregistered buckets instead of only
counting warnings.

`quiltx.acl.analyze_user_downgrades` compares each user's effective access
(roles, admin, composed bucket permissions) before and after a diff.
`--dry-run` prints a `!! DOWNGRADE` block per affected user; `--yaml` re-parses
its own output, diffs it against the captured state, and reports risks both in
the `# not captured:` notes and on stderr. Opaque (unmanaged) roles and roles
kept under a changed SSO selector are reported as undetermined; SSO and
default-role effects apply to SSO-only users, and only when the SSO document
itself changes. Callers with email-keyed `users:` entries pass `resolved_users`
(server username -> `AclUserConfig`); `applied_user_names` remains for keys that
are already usernames. With neither kwarg the keys are resolved internally by the
same rule, so a public-API caller does not silently lose email-keyed entries.

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
