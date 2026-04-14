# Direct ACL: Minimal Changes for the `simpler-stack-acl` Format

## Goal

Make `quiltx stack acl <file.yml>` **only** accept the new flat format defined
in [simpler-stack-acl.yml](simpler-stack-acl.yml). Drop support for the
three-block (`bucket_policies:` / `roles:` / `sso:`) format used by
[demo-stack-acl.yml](demo-stack-acl.yml). No backwards-compatibility shims.

This is a **direct rewrite**, not a parallel path. The old YAML schema and its
data model go away; the server-side reconciliation (Quilt `admin.*` APIs)
stays the same.

## The format, in one paragraph

A config has exactly two top-level keys: `policies:` and `roles:`.

- A **policy** lists the SSO groups that confer it (`sso.groups`), the buckets
  it grants (`buckets.read`, `buckets.read_write`), and optional config flags
  (`config.default_role`). Every user belonging to any listed group qualifies;
  their **synthetic role** is the union of all policies they qualify for.
- A **role** is static and explicit: it lists the SSO groups that receive it
  (`sso.groups`), the named policies it composes (`config.policies`), any
  inline bucket grants (`buckets.read`, `buckets.read_write`), and
  optional flags (`config.is_admin`). Users may match multiple static and
  synthetic roles; the last-matching role is selected at first login, and the
  last-used role thereafter (client-side concern — out of scope).

## Semantic model → Quilt admin API

| Source construct | Server artifact |
|---|---|
| `policies.X` (buckets block) | `admin.policies.create_managed("X", …)` — one managed policy per block |
| `policies.X` cumulative synthetic role | `admin.roles.create_managed(<synth-name>, policies=[…])` — one managed role per distinct group-audience "tier" (see below) |
| `policies.X.config.default_role: true` | Sets `default_role` on the SSO config, resolving to X's synthetic role |
| `roles.Y` with `config.policies` and/or inline buckets | One managed policy `Y__inline` for inline buckets (only when inline buckets present) + `admin.roles.create_managed("Y", policies=[…])` |
| `roles.Y.config.is_admin: true` | `admin: true` on the corresponding SSO mapping |
| `sso.groups` anywhere | Emitted as a Quilt SSO mapping: `groups contains <group> → [<role>]` |

### Synthetic-role synthesis (the one non-trivial rule)

The order of entries under `policies:` declares a cumulative audience
**ladder**: each subsequent policy's audience must be a subset of every
prior policy's audience. For each policy P (index i), synthesize one
managed role whose policies are the union
`{policies[0], policies[1], …, policies[i]}`. The role name is the
underscore-joined policy names in reverse index order (e.g.
`internal_public` for the second entry in the demo file), matching the
comment convention.

Each policy emits **one SSO mapping per listed group**, pointing at *its own*
synthesized role. Quilt's last-matching-wins rule gives users in more
privileged groups the wider role automatically — no per-subset enumeration
needed.

**Safety: the subset property is load-bearing and must be validated, not
assumed.** If policy i's groups are not a subset of policy j's groups (for
every j < i), the cumulative-union rule silently overgrants: e.g.
`public: [Contractors]` followed by `finance: [Executives]` would produce
`finance_public` and grant `public` bucket access to Executives who were
never in the `public` audience. The parser MUST reject any config that
violates this nesting. Two enforcement options:

- **Declarative (preferred):** require the author to spell out group
  containment in a top-level `groups:` section (e.g.
  `Employees: { subset_of: [Everyone] }`), and reject a ladder whose
  i-th policy is not a subset of every prior policy under that declared
  hierarchy.
- **Syntactic-only fallback:** require that each policy's `sso.groups`
  is a (non-strict) subset of the immediately prior policy's `sso.groups`
  as written. This is weaker — it cannot express "Employees ⊂ Everyone"
  unless both groups are listed — but it is unambiguous from the YAML
  alone.

Pick one and document it in user-facing errors. The order-matters contract
only becomes safe once this check exists.

## Tasks

### 1. Rewrite the parser (`quiltx/acl.py`)

- Replace `AclBucketPolicy` / `AclRole` / `AclSsoMapping` / `AclConfig`
  dataclasses with:
  - `AclPolicy(name, groups, read, read_write, default_role)`
  - `AclStaticRole(name, groups, policies, read, read_write, is_admin)`
  - `AclConfig(policies: list[AclPolicy], roles: dict[str, AclStaticRole])`
  - Preserve `policies` insertion order — it drives synthetic-role synthesis.
- Rewrite `parse_acl_config()`:
  - Reject unknown top-level keys (only `policies` and `roles`).
  - Reject the old keys (`bucket_policies`, `sso`) with a clear error pointing
    to the new format.
  - Validate `sso.groups` is a non-empty list of strings under every policy
    and role.
  - Validate `buckets.read` / `buckets.read_write` lists (reuse the existing
    `_coerce_string_list` helper).
  - Validate `config.policies` in a static role refer to known `policies:`
    entries.
  - Enforce at most one `config.default_role: true` across all policies.
  - **Enforce the ladder subset property** (see "Synthetic-role synthesis"
    above) and reject a violating config with an error that names the two
    offending policies and the groups that break the chain.
  - **Reserve the `__inline` suffix** on policy titles: reject any
    top-level `policies.X` whose name ends in `__inline`, and reject any
    static role named `Y` where the user has also declared a top-level
    policy called `Y__inline`. Synthetic role names (the underscore-joined
    cumulative names) must also not collide with any user-declared
    `policies.*` or `roles.*` entry; if they do, reject with a clear error
    naming the collision. Reserving these name shapes up front avoids the
    unmanaged-collision warn-and-skip path for generator-owned artifacts.
- Rewrite `all_buckets()` to walk the new shape.

### 2. Rewrite the diff/apply core (`quiltx/acl.py`)

- `compute_diff()`:
  - Managed-policy set = one per `policies.X` + one `Y__inline` per static
    role `Y` that has inline buckets.
  - Managed-role set = one synthetic role per policy index + one
    per static role.
  - Keep the same unmanaged-collision → warn-and-skip behaviour.
  - **Delete-protection must use the desired-state SSO and default role,
    not the server's current SSO/default.** The existing code protects any
    role still referenced by `current.sso_config_text` or equal to
    `current.default_role_name`. That rule is correct when role names are
    author-controlled and stable, but synthetic role names change on
    policy rename/reorder or default-role change. If we kept the
    current-state protection, the first apply would install new SSO and
    new synthetic roles while the old synthetic roles would survive
    because they are still referenced by the *pre-apply* SSO snapshot —
    forcing a second `stack acl` run to clean them up. Instead:
    - Compute the protection set from the **desired** SSO + desired
      default role, so roles that the new config no longer references
      are queued for deletion in the same pass.
    - Still never delete unmanaged roles; still warn on any protected
      role that the author has explicitly removed.
  - **Apply order must place SSO update before role deletes** (it
    already does in the current `apply_acl()` — preserve that). Otherwise
    the server would briefly reference a deleted role.
- `build_sso_config()`:
  - Emit one mapping per policy-group pair → synthetic role.
  - Emit one mapping per static-role-group pair → static role, with
    `admin:` reflecting `config.is_admin`.
  - `default_role` comes from the policy marked `config.default_role: true`,
    resolved to that policy's synthetic role name.
- `apply_acl()`: unchanged in shape; it just iterates whatever the diff
  produced.

### 3. CLI (`quiltx/tools/stack/acl.py`)

- Keep `config_file`, `--yes`, `--dry-run`, `--verbose` flags unchanged.
- Drop `_resolve_default_role_name()` interactive prompt — the default role
  is now declared in YAML via `config.default_role: true`. If none is
  declared, no default is set (matches current safety posture).
- Update the `stack acl` help text to reference the new format.

### 4. Printing

- Update `print_diff()` / `print_current_state()` / `_print_verbose_state()`
  to render the new constructs (`policies` with groups, synthesized roles,
  static roles with is_admin). Keep the `+ / ~ / - / =` prefix vocabulary.
- In verbose output, annotate each synthetic role with
  "(synthesized from policies P1, P2, …)" so operators can see why it exists.

## Design points

1. **Flat `policies:`, not `bucket_policies:`.** A single source of truth
   that combines bucket grants with the SSO groups that confer them. This is
   the primary ergonomic win of the new format; preserve it — do not
   reintroduce an internal three-block model.
2. **Order matters in `policies:`.** Document-order is a load-bearing
   semantic contract. Call it out in the parser error messages and in user
   docs; surface the synthesized role names in `--verbose` so operators can
   verify their intent.
3. **Synthesized role names are derived.** Do not let users name them;
   derive them deterministically from policy names so that re-runs produce
   stable output.
4. **Inline buckets on static roles get a hidden managed policy.** The Quilt
   server model composes roles from policies, not from raw permissions, so
   inline `buckets.*` under a role become a managed policy `Y__inline`. Mark
   these clearly in diff output so operators aren't surprised by the extra
   artifact.
5. **No default-role prompt.** The old CLI prompted when no role had
   `default: true`; the new format makes the choice declarative on a
   **policy**, not a role. If omitted, no default is set.
6. **Reject the old format loudly.** Do not silently coerce. A config with
   `bucket_policies:` or a top-level `sso:` block must fail with an error
   that names the new keys (`policies`, `roles`) and links to the updated
   example.
7. **Out of scope (for this change):** conditions / runtime-resolved grants
   from [dynamic-roles.yaml](dynamic-roles.yaml), `last-used role` persistence,
   per-request role selection. These remain future work; the parser should
   reject their syntax rather than half-implement it.

## Testing

Update / rewrite `tests/test_acl.py`:

- **Parsing**
  - Accept a minimal valid config (just `policies:` with one entry).
  - Accept the full `simpler-stack-acl.yml` verbatim.
  - Reject `bucket_policies:` and top-level `sso:` with a helpful message.
  - Reject unknown top-level keys, non-list `sso.groups`, non-bool
    `config.is_admin` / `config.default_role`.
  - Reject a static role whose `config.policies` references an unknown
    policy.
  - Reject more than one policy with `config.default_role: true`.
- **Synthetic-role synthesis**
  - Two-policy ladder produces two synthesized roles with the expected
    cumulative policy sets and names.
  - Single-policy config produces one synthesized role.
  - Reordering `policies:` produces different (but still deterministic)
    role names.
- **Static-role composition**
  - `config.policies` plus inline buckets produces the role + the
    `Y__inline` managed policy in the diff.
  - `config.is_admin: true` appears on the emitted SSO mapping only for that
    role's groups.
- **SSO config emission**
  - One mapping per `(group, role)` pair.
  - `default_role` populated iff a policy has `config.default_role: true`.
- **Diff / apply**
  - Re-running an unchanged config against the already-applied state
    prints "up to date" (true idempotency — no second pass needed).
  - Unmanaged-name collisions warn and skip (preserve existing behaviour).
  - Changing a policy's groups moves the corresponding SSO mapping.
  - **Rename / reorder cleanup in a single pass**: starting from a stack
    already reconciled to config A, a single run of `stack acl B` where
    B renames a policy, reorders `policies:`, or moves
    `config.default_role` must produce an empty diff on the *second*
    run. Assert this explicitly — it is the regression test for the
    desired-state-protection fix in `compute_diff()`.

Keep the Quilt `admin.*` modules mocked as today; do not add network tests.

Also add a CLI-integration test that feeds
`spec/060-stack-acl/simpler-stack-acl.yml` through `parse_acl_config()` and
`compute_diff()` against an empty `CurrentState`, asserting the expected
create-list — this guards against drift between the spec example and the
parser.

## Docs

- **[README.md](../../README.md)**: the user-facing "Stack ACL" section
  currently shows a `bucket_policies:` / `roles:` / `sso:` example and
  prose describing "buckets, policies, roles, and SSO mappings" as the
  reconciled surface. Rewrite it:
  - Replace the example block with the contents (or a trimmed form) of
    `spec/060-stack-acl/simpler-stack-acl.yml`.
  - Update the opening sentence to describe the new model: two top-level
    blocks (`policies:` and `roles:`), synthetic roles composed from
    policies the user qualifies for, static roles composed explicitly.
  - Explain the order-matters contract for `policies:` with the
    `public` / `internal_public` example so readers understand why
    reordering changes outcomes.
  - Keep the existing `uvx quiltx stack acl …` command-line examples —
    they don't change.
- **[CLAUDE.md](../../CLAUDE.md)**: update the `Stack API` / `stack acl`
  blurb to link `spec/060-stack-acl/simpler-stack-acl.yml` as the canonical
  example and note that the old three-block format is gone.
- **[CHANGELOG.md](../../CHANGELOG.md)**: new entry under an unreleased
  version — "BREAKING: `quiltx stack acl` now only accepts the flat
  `policies:` / `roles:` format; see
  `spec/060-stack-acl/simpler-stack-acl.yml`." Bump minor (or major) in
  `pyproject.toml` per the repo's release convention.
- **[README_DEV.md](../../README_DEV.md)**: audit for references to the
  old dataclass names (`AclBucketPolicy`, `AclRole`, `AclSsoMapping`) or
  the old YAML keys; update to the new names (`AclPolicy`,
  `AclStaticRole`) and the new YAML shape.
- **`spec/060-stack-acl/`**: leave the historical docs (01–07) in place as
  background; this file (08) is the current spec. Delete
  `demo-stack-acl.yml` once the parser refuses it, to avoid confusion.
- **CLI help text**: one-line usage example in `build_parser()` description.

## Verification

1. `./poe test` — unit tests pass.
2. Manual: `./poe run stack acl spec/060-stack-acl/simpler-stack-acl.yml
   --dry-run --verbose` against a dev stack; confirm the diff shows
   `public` and `internal_public` synthesized roles with the cumulative
   policy sets.
3. Manual: `./poe run stack acl spec/060-stack-acl/demo-stack-acl.yml` —
   must fail with a message pointing at the new format.
4. Manual: apply with `--yes`, verify in the Quilt admin UI, then re-run —
   must print "Stack ACL is up to date". **This promise depends on the
   desired-state-protection rule in `compute_diff()`**: if the second run
   still shows stale synthetic roles queued for deletion, the delete-
   protection set is being computed from the current SSO snapshot instead
   of the desired one — fix `compute_diff()` before shipping.
5. Manual: starting from a stack reconciled to `simpler-stack-acl.yml`,
   rename `internal` → `employees` in the same file and apply — the
   second re-run must still print "up to date" with no leftover
   `internal_public` managed role.
6. Manual: feed a deliberately-broken ladder (e.g. `public:
   [Contractors]` then `finance: [Executives]`) — the parser must
   refuse it with an error that names both policies and the groups
   that violate the subset requirement.
