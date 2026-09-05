# quiltx

[![PyPI](https://img.shields.io/pypi/v/quiltx)](https://pypi.org/project/quiltx/)

Quilt extension toolkit for working with [Quilt](https://quiltdata.com) catalogs.

## Quick start

```bash
# See available tools
uvx quiltx

# Sign in to a catalog: mints a qk_... API key from your username/password,
# stores it in your system keyring, and sets it as the default catalog.
uvx quiltx catalog login --catalog open.quiltdata.com --username you@example.com
uvx quiltx catalog default open.quiltdata.com

# Get help for any tool
uvx quiltx <tool> --help
```

`quiltx catalog login` accepts either `--username` with a password supplied by
an interactive prompt, `--password-stdin`, `QUILTX_PASSWORD`, or the legacy
`--password` flag (admin catalogs), or `--api-key qk_...` (paste an existing
key, or the only path for SSO-only catalogs — see below). Both DNS names
(`open.quiltdata.com`) and full URLs (`https://open.quiltdata.com/`) are
accepted as `--catalog` arguments and normalized to the bare DNS.

For CI, use `--no-store` to avoid keyring and plaintext-file persistence. The
command prints only the minted key to stdout, so it can be captured for reuse:

```bash
export QUILTX_API_KEY="$(
  printf '%s\n' "$CATALOG_PASSWORD" |
    uvx quiltx catalog login --catalog open.quiltdata.com \
      --username you@example.com --password-stdin --no-store
)"
```

Alternatively, set `QUILTX_PASSWORD` and omit `--password-stdin`. Status
messages go to stderr; the API key is the only stdout output in no-store mode.

### Tools

- **bucket** — Register cross-account S3 buckets with Quilt (policy, SNS, notifications)
- **catalog** — Manage Quilt catalogs:
  - **catalog login** — Mint and store a `qk_...` API key from username/password (or paste one with `--api-key`)
  - **catalog default** — Read, set, or clear the default catalog (auto-runs `login` when the DNS has no stored key)
  - **catalog list** — List catalogs with stored credentials
  - **catalog forget** — Delete the keyring entry for a catalog
  - **catalog acl** — Declarative access-control-list (ACL) reconciliation from YAML
  - **catalog stack** — Discover the Quilt CloudFormation stack and cache metadata
- **ecs** — ECS task tools:
  - **ecs logs** — Display/tail catalog CloudWatch logs and update ECS log level
  - **ecs shell** — Interactive shell access to running ECS tasks via Session Manager
  - **ecs status** — Show or wait for ECS service rollout status
  - **ecs run-migration** — Re-run the registry migration task for a stack

### Python API

See [README_DEV.md](README_DEV.md) for programmatic usage of ECS, ACL, config,
and stack APIs.

## Bucket registration

`quiltx bucket add BUCKET` defaults to bucket-owner mode: it uses your local
AWS profile to probe the bucket, update the bucket policy, configure SNS, and
wire S3 notifications before registering the bucket with the catalog.

When the bucket owner and catalog operator are different people, split setup
into two credential-isolated steps. The bucket owner needs AWS credentials only
(no catalog configuration or API key):

```bash
uvx quiltx bucket prepare my-bucket \
  --control-account-id 123456789012 \
  --json --yes > bucket-handoff.json
```

Grants accumulate. Preparing a bucket adds the principals you name and keeps the
ones already in the policy, so a bucket registered in two catalogs does not lose
one stack's access when it is prepared for the other. `--dry-run` and the
confirmation prompt list the principals already granted, added, and removed, so
nothing changes silently. Withdraw access deliberately:

```bash
uvx quiltx bucket revoke my-bucket --control-account-id 123456789012 --dry-run
```

`revoke` rewrites only the two cross-account Quilt statements; bucket
notifications and the SNS topic stay in place because other stacks may still
consume them. Removing the last Quilt principal drops the Quilt statement and
keeps the rest of the bucket policy; only when that statement was the sole one
in the document is the policy deleted, since S3 rejects an empty statement list.
`--dry-run` says so explicitly when it applies.

Use repeatable `--principal arn:aws:iam::123456789012:role/...` options to name
specific Quilt roles rather than the control-account root. Account root and IAM
user ARNs are accepted too, so a shared bucket can name each consuming stack's
control account.

Because grants accumulate, naming a narrower set does not withdraw a wider one.
Preparing with `--principal <role>` on a bucket that already grants
`arn:aws:iam::123456789012:root` leaves that root grant in place; it is listed
under `Kept` in the output rather than dropped. Narrowing is two deliberate
steps:

```bash
uvx quiltx bucket prepare my-bucket --principal arn:aws:iam::123456789012:role/SomeRole
uvx quiltx bucket revoke my-bucket --control-account-id 123456789012
```

If you don't know the control account ID, pass
`--catalog example.quiltdata.com` instead: any
logged-in catalog user (no admin role needed) can derive it from cached stack
metadata or from credentials the catalog's own registry mints. If the catalog
will not mint credentials, the command fails and asks for an explicit
`--control-account-id` or `--principal` rather than guessing from your local AWS
profile. `--dry-run` prints the
exact final S3 policy, SNS policy, and notification configuration without any
writes. Preparation preserves unrelated policies and compatible notifications,
and stops with actionable details when an object-event notification overlaps.
The JSON handoff contains only the bucket, region, owning account, effective
principals, and SNS topic ARN; it contains no credentials.

The catalog operator then needs catalog-admin credentials only, not access to
the bucket owner's AWS account:

```bash
uvx quiltx bucket add my-bucket --catalog example.quiltdata.com --no-preflight
```

Use `--no-preflight` when the catalog stack can already access the bucket but
your local AWS identity cannot or should not modify it, such as public AWS Open
Data buckets or buckets already plumbed by Quilt infrastructure:

```bash
uvx quiltx bucket add igvf-public --catalog example.quiltdata.com --no-preflight
uvx quiltx catalog acl acl.yml --catalog example.quiltdata.com --no-preflight --yes
```

`--no-preflight` submits the GraphQL registration directly, lets the stack probe
with its IAM, and skips local S3/SNS setup. It still verifies afterwards — the
cross-account path is the one most likely to be misconfigured — so pass
`--no-test` to opt out. Set `QUILTX_NO_PREFLIGHT=1` to use the same mode for
scripted runs.

On `catalog acl` the flag applies to every new bucket in the run and is not
recorded anywhere, so the next plain apply hits the same failure. Mark the
individual bucket instead with
[`config.no_preflight` under `buckets:`](#pre-prepared-buckets).

### Verifying access

`quiltx bucket test BUCKET` reports three independent checks:

1. **Registration** — the bucket has a catalog row.
2. **Live access** — the catalog re-validates the bucket server-side with the
   stack's own service identity, so an empty bucket passes and revoked access
   fails even when stale search-index entries remain. Failures name the failed
   capability, the Quilt control account, and the stack principal. The probe
   resubmits the bucket's existing catalog configuration unchanged to trigger
   that re-validation; set `QUILTX_NO_LIVE_PROBE=1` to skip it where no bucket
   mutation is acceptable.
3. **Index wiring** — the search index has entries, which proves SNS to SQS
   delivery is live. Once live access is verified, an empty index is a warning
   rather than a failure, since indexing lags registration and empty buckets
   never index. Pass `--require-index` to make it fatal.

Before a bucket is registered, check a cross-account grant straight from the
handoff with control-account credentials:

```bash
uvx quiltx bucket test my-bucket --catalog example.quiltdata.com \
  --pre-registration --profile control-account
```

That mode treats "not registered" as expected and checks what is checkable:
the bucket is reachable, `GetBucketNotification` is readable, and the SNS topic
policy grants `Subscribe`/`GetTopicAttributes`. Topic policies are read
conservatively — an explicit `Deny` counts, and a condition-bearing `Allow` is
reported as conditional rather than assumed to apply. It reports the principal that
ran the checks and fails loudly when that principal is not in the catalog's
control account — which is how a grant issued to the wrong account surfaces at
handoff time instead of as an opaque `AccessDenied` later.

### Persistent install (optional)

```bash
uv tool install -U quiltx
# Now use without the uvx prefix:
quiltx --list
```

## Catalog ACL

`quiltx catalog acl` declaratively manages a Quilt stack's access control lists
(ACLs) from one YAML file with top-level `policies:`, `roles:`, and optional
`users:` blocks. Policy audiences synthesize cumulative managed roles; reusable
policies can opt out with `config.synthesize: false`; and static roles compose
named policies, optional inline bucket grants, and optional SSO selectors.
Instead of clicking through the catalog admin UI, you define the desired state
in version-controlled YAML and let the tool reconcile it against the server.

### YAML example

```yaml
# Access control lists for a Quilt stack
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [quilt-example]
    config.default_role: true
  internal:
    sso.groups: [Employees]
    buckets.read_write: [quilt-bake, quilt-dev]
    buckets.read: [quilt-leadership]
    config.is_admin: true

roles:
  exec:
    sso.groups: [Executives]
    config.policies: [public, internal]
    buckets.read_write: [quilt-leadership]
    config.is_admin: true
```

Policy order matters. In this example `public` synthesizes the `public` role,
and `internal` synthesizes `internal_public`, which cumulatively includes both
`public` and `internal`. Reordering the policies changes those synthesized role
names and who receives which cumulative grants.

Policy `config.is_admin` also composes cumulatively for synthesized roles.
Unset is neutral, `true` grants admin, and an explicit `false` vetoes any prior
`true` in that generated role and is reported as a warning.

`config.default_role: true` reconciles the settings-level role assigned to new
password signups. A selector-less static role may be the default; when the file
also generates SSO configuration, the same role is used as its fallback default.
Files with any `sso.<claim>` selectors must declare exactly one default role.

### Built-in unmanaged roles

Every catalog ships with unmanaged roles (IAM-role-backed, created by the stack
rather than the registry). `config.unmanaged: true` references one by name:

```yaml
roles:
  ReadQuiltBucket:
    config.unmanaged: true
  ReadWriteQuiltBucket:
    config.unmanaged: true
    sso.groups: [Employees]
```

Referenced this way, a role stays addressable from `users:`, `sso.<claim>`
selectors, and `config.default_role` while quiltx never creates, updates, or
deletes it. Because their bucket grants live in IAM rather than the registry,
unmanaged roles cannot carry `config.policies` or `buckets.*` grants. The two
QuiltStack built-ins are the exception for registration references:
`ReadQuiltBucket.buckets.read` and
`ReadWriteQuiltBucket.buckets.read_write` may list buckets that the ACL should
register, but those fields never modify the roles' IAM permissions. Other
bucket fields and bucket fields on custom unmanaged roles remain invalid.

`--yaml` always emits entries for the unmanaged roles it finds, even when no
user or selector currently references them. Registered buckets not already
represented by managed permissions are listed on both built-in roles, so a
capture can register them when replayed without duplicating explicit grants.

### Default policies

`config.default_policy: true` marks a policy as the floor every managed role
stands on. It is composed into each role's policy list, last and deduped, so a
role that already names the policy is unchanged:

```yaml
policies:
  general:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [quilt-open]
```

This is what `config.default_role` cannot express. The default role is a
fallback: the registry assigns it only when an authenticated user's SSO claims
matched no mapping at all. A specific grant therefore costs a user the general
one — someone named in a narrow role's `sso.email` matches that mapping, never
reaches the default role, and loses the open buckets unless every narrow role
repeats the general policy. A default policy composes into the roles a user
already matched, so it grants the same permissions without adding a role to
anyone's set and cannot disturb which role the catalog treats as active.

The flag requires `config.synthesize: false`. A synthesizing policy is a ladder
rung whose `sso.<claim>` selector declares its audience; granting that rung to
the rungs below it would hand its buckets to those broader audiences while
leaving their synthesized role names unchanged, so the combination is rejected.

Unmanaged roles never receive a default policy, because their permissions live
in IAM and quiltx does not modify them. A user whose only role is unmanaged must
also match a managed role's selector to stand on the floor; a config that
declares both a default policy and an unmanaged role reports this as a nonfatal
notice (`NONFATAL:` in the plan). It is what the two flags together mean, not
something that went wrong, so it does not fail an apply.

Composing into every role makes one policy a dependency of all of them, so a
default policy the server does not hold blocks every role, not just the roles
that named it. Since no role could be reconciled, the apply stops there — after
the policy phase, before any role is created, updated or deleted and before any
policy is deleted. Continuing would have deleted the roles and policies the file
drops while provably unable to create the ones it adds, leaving working access
torn down with nothing to replace it. The policy changes that did land stay, the
run names the policy once as the cause, and it exits non-zero:

```text
!! DEFAULT POLICY MISSING: 1 default policy blocked every managed role in this apply:
  - Policy 'general' is declared config.default_policy: true, so every managed role composes it; it does not exist, so this apply stopped before touching 3 role(s) and deleted nothing: public, internal_public, exec.
```

`--yaml` does not re-emit the flag. The server has no notion of a default
policy, and every captured role already lists it in its composed
`config.policies`, so the capture replays to the same state. Re-add the flag by
hand to keep the file shorter and to re-arm it for roles added later.

### Pre-prepared buckets

The optional `buckets:` block declares per-bucket registration options. A key
there references the bucket on its own, so it can be registered before any role
or policy grants access to it:

```yaml
roles:
  SierraGeneralRole:
    buckets.read_write: [sierra-general]
buckets:
  sierra-general:
    config.no_preflight: true
```

`config.no_preflight: true` registers the bucket through GraphQL only and leaves
its AWS setup alone. Use it for a bucket owned by another account that was
already prepared owner-side with
[`quiltx bucket prepare`](#bucket-registration): the SNS topic exists and the
catalog's control account holds the grant, but the identity applying the ACL is
a catalog admin rather than the bucket owner, so it cannot read or write that
bucket's policy. Without the flag, preflight fails and the bucket never
registers.

The CLI's `--no-preflight` says the same thing for every new bucket in the run
and remains a global override. The difference is durability and scope: declared
in the file, the fact stays with the bucket, so the next plain apply — or a CI
job that does not know which bucket is special — behaves the same way, and the
buckets this identity does own still get their local setup. `--dry-run` names
each bucket that would be registered via GraphQL only and where that mode came
from.

Captures do not re-emit the block. The registry records no per-bucket
registration mode, so it cannot tell a bucket prepared in another account from
one this identity owns. Replaying a capture against the catalog it came from is
unaffected — those buckets are registered already — but re-add the flag by hand
before replaying onto a catalog that has yet to register such a bucket.

A bucket that does not register is reported as its own error block, naming the
bucket and the reason, and the command exits non-zero. The apply continues past
it deliberately, so the rest of the file still lands, but permissions that
reference the bucket cannot be applied and are reported too:

```text
!! BUCKET REGISTRATION FAILED: 1 bucket(s) not registered:
  - sierra-general: An error occurred (AccessDenied) when calling GetBucketLocation
```

### Users

`users:` reconciles the active role, ordered extra roles, and admin status of
accounts that already exist. The `users:` block itself never creates or deletes
an account — a key that matches nothing is reported and skipped. Onboarding is a
separate, opt-in command-line step; see
[Creating users from sso.email rosters](#creating-users-from-ssoemail-rosters).
Nothing in quiltx ever deletes a user.

```yaml
users:
  alice:                  # admin-created account: the username is a handle
    role: exec
    extra_roles: [internal_public]
    admin: true
  bob@example.com:        # SSO self-registration: the username is the email
    role: internal_public
```

Both shapes appear in one file because the registry derives an SSO
self-registration's username from its email address, while an admin-created
account must use a `^[a-z][a-z0-9_]*$` handle. Each key is therefore resolved
against the server by exact username first, then by a unique case-insensitive
email match, so writing an email works even when the account uses a handle.

A key that names an account always means that account, even when someone else
holds that string as their email address: precedence decides, and the clash is
reported as a warning naming both accounts so you can rekey if you meant the
other person. Making it fatal would reject this tool's own `--yaml` capture, which
keys every entry by username.

Two errors remain. A key that names no account and is the email of two of them
has nothing to decide it, and two keys that resolve to the same account are two
conflicting statements about one person. Both name the conflict and stop. A key
that matches nothing is reported as a nonfatal notice and skipped, so check the
output when an expected change does not appear. Running `quiltx catalog acl` with
no config file lists both identifiers for every account.

### Creating users from sso.email rosters

Because `users:` only ever reaches accounts that exist, an ACL file cannot
onboard anyone: granting a role to someone who has never logged in needs an
admin-UI invite or a first SSO login, after which you re-run the tool. The
`--create-and-email-users` flag closes that gap by creating an account for every
`sso.email` address the server does not already hold:

```bash
uvx quiltx catalog acl config.yml --dry-run --create-and-email-users
uvx quiltx catalog acl config.yml --yes --create-and-email-users
```

Creation is driven by `sso.email`, not by `users:`, and there is no config key
for it. `sso.email` is already a per-role roster of individuals keyed by a field
that can only be an email, which makes it the better source in three ways. There
is no identifier ambiguity, because unlike a `users:` key an `sso.email` value is
never a handle. There is no drift, because the role is implied by the nesting, so
the role assigned at creation and the role the SSO mapping grants are the same
declaration; a `users:`-assigned role would be overwritten anyway, since every
SSO login recomputes roles from the SSO config and replaces the set. `sso.hd` and
`sso.groups` contribute nobody: a domain or a group names no individual, so there
is nobody to create.

An account created through the admin API carries a username quiltx chose:
`quilt3.admin.users.create` requires the field, so quiltx cannot use the
registry's own `email[:64]` derivation and must supply a name matching
`^[a-z][a-z0-9_]*$`. It folds the whole address — `alice@example.com` becomes
`alice_example_com`. The domain is folded in rather than dropped because a
handle built from the local part alone maps `alice@example.com` and
`alice@contractor.example` onto one name, and only one account can hold it; a
catalog with an outside collaborator is exactly where this flag gets used. The
handle is an administrative label, not the identity — first SSO login matches the
pre-created account by email, so the person signs in as themselves regardless of
what the account is called.

Folding is not reversible or unique: `.` and `+` both become `_`, and the name is
capped at 64 characters. So the derived handle is checked against the catalog's
existing usernames *and* against the rest of the roster, and any clash refuses
those addresses with a warning rather than picking a winner or appending a
suffix — a suffix would make somebody's username depend on what else happened to
be in the file.

An address any account already answers for is never created again, decided by
the same resolution `users:` keys get: username first, then a unique email match.
For a roster it is almost always the email that matches, since a folded handle is
not the address it came from. When several roles name the same person, the last
declaration becomes the active role and the earlier ones become extra roles,
matching `union_roles: true` and the last-matching first-login pick. An address
two accounts already answer for is reported as a nonfatal notice: nothing needs
creating, so it is counted once as already onboarded and does not fail the run,
while two accounts sharing one address is still worth knowing about.

**An address that looks like a rename is refused, not onboarded twice.** quiltx
never changes an existing account's email, so an address the server does not hold
is either a new person or somebody whose address changed — and a changed address
is usually *why* you are editing the roster. Nothing in the data distinguishes
them, and the two checks above do not help: `robbyqbutler@protonmail.com`,
`robbyqbutler@pm.me` and an account named `robbyqbutler` are three different
strings. So an address whose local part an existing account already uses, as its
username or in its own address, is reported and skipped:

```text
Warning: Roster address 'robbyqbutler@pm.me' has no account, but its local part 'robbyqbutler' is already used by 'robbyqbutler' (email robbyqbutler@protonmail.com); not created. ...
```

Set the existing account's email to the new address if it is the same person, or
create the account by hand if it is not. This is deliberately cautious in one
direction: `alice@example.com` and `alice@partner.example` get separate handles
but trigger this warning, because merging two people and splitting one person are
both worse than asking.

An address is only created when every role it names exists at that moment. The
registry rejects a creation naming a role it does not have, and whether it mails
the welcome before failing is not something quiltx controls, so the attempt is
not made. `--dry-run` counts the roles this file declares, since nothing has been
applied yet and a fresh catalog would otherwise flag everybody. A real run does
not: it happens after the apply and asks the server what actually landed, so a
role whose creation failed takes only its own addresses down with it rather than
turning into a creation the registry will refuse. A `config.unmanaged: true` role
the server does not hold is refused either way, because quiltx never creates one.
That address is reported and skipped. An unmanaged role that *does* exist is created
into, because its selector would grant it at first login anyway — note that its
permissions are IAM-backed, so the downgrade analysis reports that account's
access as undetermined rather than enumerating it.

**The mail cannot be recalled.** The registry's create mutation generates a
password-reset link and sends a welcome email, with no suppress flag. That is
why the flag lives only on the command line: a config default would make the
*first* apply the irreversible one, and that is the apply you run before anyone
has reviewed the roster. Real files carry community rosters whose addresses have
no idea the stack exists.

The addresses are therefore printed in full before anything is sent, and
confirmed or passed `--yes`:

```text
!! CREATE AND EMAIL: 2 account(s) will be created and sent a welcome and password-reset email:
  - alice@example.com -> user alice_example_com, roles internal_public
  - bob@example.com -> user bob_example_com, roles exec, internal_public
The registry sends this mail as part of creation; it cannot be recalled.
Create and email 2 account(s)? [y/N]:
```

When no address can be created, there is no prompt, no mail and no registry
call — just the reasons and a non-zero exit:

```text
No accounts to create: 0 roster address(es) already have one and 2 cannot be created.
Warning: Roster address 'a.b@example.com' derives username 'a_b_example_com', which is also derived by 'a+b@example.com'; not created. A username belongs to one account, so quiltx will not decide which of these addresses gets it: create these accounts by hand.
```

`--dry-run` creates nobody and mails nobody, and still names every address. A
run that would create more than 10 accounts is refused; re-run with
`--max-created-users N` to raise the cap once the printed list has been
reviewed.

The three ways a creation does not happen are not the same. Declining the prompt
creates nobody, and so does declining the earlier apply prompt, which returns
before this step. Refusing over the cap creates nobody either. Only a *failed*
creation is per-address: the rest of the roster still gets its accounts. All
three are warnings, so the command exits non-zero in each case.

Creation runs after roles are reconciled — the registry rejects a creation naming
a role it does not hold — and it is additive: accounts absent from the rosters are
left alone.

### Downgrade warnings

Both export and reconciliation compare each existing user's effective access
(role, extra roles, admin, and composed bucket permissions) before and after.

`--dry-run` prints a per-user block for anything that would reduce access,
including reductions caused indirectly by a narrowed policy, a deleted role, a
replaced SSO mapping, or a changed default role:

```text
!! DOWNGRADE: user alice would lose access
    primary role: Analysts -> Default
    extra roles: Leads -> (none)
    admin: true -> false
    lost permissions: READ_WRITE:quilt-bake
    cause: role 'Analysts' would be deleted
    cause: falls back to the default role 'Default'
```

`--yaml` re-parses its own output and diffs it against the state it captured. If
replaying the file would not preserve someone's access, the affected users are
listed in the generated `# not captured:` notes and repeated on stderr, so the
warning is still visible when stdout is redirected to a file.

Limitations: role renames and reassignments that preserve permissions are not
flagged, and neither are increases. Permissions granted by an unmanaged role are
invisible to the registry, so losing one is reported as undetermined rather than
quantified. SSO mapping and default-role effects are evaluated for SSO-only
users, whose roles are recomputed at each login; a password user keeps their
stored assignment until something explicitly changes it. The registry does not
expose a user's IdP claims, so when a role survives under a different selector
the outcome is reported as undetermined rather than resolved.

### Usage

With no config file, the command reports the complete server ACL state, including
users and their active and extra role assignments. Pass `--json` for a complete
machine-readable reporting export, or `--yaml` for a replayable ACL config that
can be saved and passed back to `catalog acl --dry-run`. Read the stderr output
of `--yaml` before replaying: that is where downgrade risks are reported.

```bash
# Show current server ACL state
uvx quiltx catalog acl

# Export reporting data as JSON
uvx quiltx catalog acl --json

# Capture replayable ACL YAML
uvx quiltx catalog acl --yaml > default-acl.yaml
uvx quiltx catalog acl default-acl.yaml --dry-run

# Preview changes from a hand-authored config
uvx quiltx catalog acl config.yml --dry-run

# Preview with full detail
uvx quiltx catalog acl config.yml --dry-run --verbose

# Apply changes (with confirmation prompt)
uvx quiltx catalog acl config.yml

# Apply without prompting
uvx quiltx catalog acl config.yml --yes

# Also create (and mail) accounts for sso.email addresses with no user
uvx quiltx catalog acl config.yml --yes --create-and-email-users
```

## SSO-only catalogs

`quiltx catalog login --username --password` only works on catalogs that
accept username/password at `/api/login`. SSO-only catalogs reject U/P with
the catalog's own error (e.g. "SSO is required"). In that case:

1. Open the catalog UI in your browser and mint an API key from the
   account/keys page.
2. Paste it with `--api-key`:

```bash
uvx quiltx catalog login --catalog quilt.example.com --api-key qk_...
```

## Corporate TLS proxies

If catalog requests fail with `CERTIFICATE_VERIFY_FAILED` (common on
networks with TLS-inspection proxies or self-signed catalog certs), point
Python at your organization's CA bundle by exporting one of the standard
environment variables before running quiltx:

```bash
export SSL_CERT_FILE=/path/to/corp-root.pem
# or: export REQUESTS_CA_BUNDLE=/path/to/corp-root.pem

uvx quiltx catalog login --catalog quilt.example.com --username you@example.com
```

## Local catalog testing (`--insecure`)

When developing against a local catalog build, pass `--insecure` to allow
plain `http://localhost`:

```bash
uvx quiltx catalog login --catalog localhost --insecure --username admin
uvx quiltx catalog acl --catalog localhost --insecure config.yml
```

`--insecure` is **only** accepted when the catalog DNS resolves to
`localhost`; any other target is rejected. The flag is never persisted —
it must be passed on every command that hits the catalog.

## ECS

```bash
# Open an interactive shell inside the registry service task
uvx quiltx ecs shell

# Display and tail CloudWatch logs
uvx quiltx ecs logs

# Dry-run setting the registry container log level
uvx quiltx ecs logs --set-level DEBUG

# Apply a log-level change and wait for service stability
uvx quiltx ecs logs --set-level DEBUG --yes

# Show ECS service rollout status
uvx quiltx ecs status

# Wait for ECS service rollout stability
uvx quiltx ecs status --wait

# Dry-run the registry migration relaunch using cached stack metadata
uvx quiltx ecs run-migration --dry-run

# Start the migration task and wait for completion
uvx quiltx ecs run-migration
```

## License

MIT
