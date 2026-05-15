# No-Preflight Bucket Registration

## Problem

quiltx and the catalog admin UI both register buckets by submitting the same
`bucketAdd` GraphQL mutation to the registry. They differ in **what they do
before that submission** — and that pre-submission difference is what fails
today.

**The two credential systems quiltx holds, and what neither one is:**

| Credential | Source | Used for | What it is *not* |
| --- | --- | --- | --- |
| `qk_...` catalog API key | minted by `quiltx catalog login`; stored per-DNS in the OS keyring | authenticating the GraphQL `bucketAdd` call | **not** AWS credentials |
| local AWS profile (`AWS_PROFILE`, `~/.aws/...`) | standard boto3 chain; falls back across every other configured profile via [`resolve_bucket_session`](../quiltx/bucket.py#L30-L92) | `GetBucketLocation`, `GetBucketPolicy`, `PutBucketPolicy`, SNS topic create + subscribe, bucket-notification config | **not** the stack's IAM |

**The stack's IAM role is server-side only.** quiltx can ask the stack to do
things on its behalf via GraphQL, but it cannot *become* the stack for direct
S3 calls. That's the asymmetry: the admin UI doesn't make direct S3 calls at
all — it submits the mutation, and the stack probes the bucket using its own
IAM. quiltx makes direct S3 calls *first*, using your local profile, and
only then submits the mutation.

**Why quiltx does that today (and why it's right in one specific case):**
the local AWS routine is *bucket-owner setup* — it merges
`QuiltCrossAccountAccess` into the bucket policy and wires up an SNS topic
so the stack can subscribe to object-change events. This is necessary and
correct when the caller **owns the bucket in a separate AWS account** and
needs to grant the Quilt control account access. In that case, the stack
*cannot* set up access for itself — only the bucket owner can — so quiltx
must do it client-side with the owner's creds.

**The cases where it's wrong:**

1. **Public AWS Open Data buckets** (e.g. `igvf-public`). The caller cannot
   modify the bucket policy and does not need to — the stack already has
   read access via public anonymous reads or the AWS Open Data program.
   Local `GetBucketLocation` fails with `AccessDenied` *even with
   `--no-sign-request`*, because the bucket's policy doesn't grant
   bucket-metadata operations to external callers.
2. **Buckets owned by the Quilt org's central account** (e.g.
   `quilt-example-bucket`). Cross-account access is plumbed once by Quilt
   infrastructure and applies to every catalog stack. The local user has
   no `GetBucketPolicy` permission on someone else's bucket and shouldn't.
   Local probe fails with `AccessDenied`.

In both cases the error message blames the wrong thing: the user sees
"AccessDenied" against a bucket the catalog can actually read, with no
indication that the failure is in quiltx's *local* pre-flight and not in
the registry's actual ability to register the bucket.

**The Alexion dev stack incident** that surfaced this:
`quiltx catalog acl alexion-acl.yaml --catalog alexion.dev.quilttest.com --yes`
failed midway on `igvf-public` and `quilt-example-bucket`. The local IAM
user `arn:aws:iam::712023778557:user/ernest-staging` lacks
`s3:GetBucketLocation` and `s3:GetBucketPolicy` on those buckets. The
catalog admin UI, by contrast, registers both buckets fine in a few clicks
— because it never runs the local pre-flight. The half-completed
reconciliation triggered an auto-reset cascade that detached the operator
from their roles and left SSO config drifted, requiring manual recovery.

The fix is to give quiltx a path that **mirrors the admin UI**: submit the
GraphQL `bucketAdd` mutation directly, let the stack probe with its own
IAM, and surface the structured GraphQL error union (`BucketDoesNotExist`,
`InsufficientPermissions`, etc.) — mapping each union typename to a
typename-tagged, actionable CLI message rather than dropping it on the
floor. The local owner-setup routine
stays available for the genuine cross-account-grant case where it is the
only thing that can work — but it stops being the only option.

## Goal

Add a `--no-preflight` flag that **skips the local pre-flight
bucket-owner setup** (`GetBucketLocation`, `GetBucketPolicy` /
`PutBucketPolicy`, SNS topic creation, bucket-notification configuration)
and registers the bucket via the registry's `bucketAdd` GraphQL mutation
alone — letting the stack probe the bucket using its own IAM, exactly like
the catalog admin UI does today.

The current default is bucket-owner-mode: quiltx assumes the caller owns the
target bucket in a separate AWS account and needs to grant the Quilt control
account cross-account access. That fails (with opaque AccessDenied) for the
two cases described in **Problem** above. `--no-preflight` opts out of that
routine and yields the admin-UI behavior.

## Naming

Chosen: **`--no-preflight`**. The term names what's skipped: the local
pre-flight pass (probe + policy edits + SNS plumbing) that runs *before* the
GraphQL submission. Alternatives considered:

| Name | Implies | Reason rejected |
| --- | --- | --- |
| `--no-probe` | Just the `GetBucketLocation` call | Understates — we skip the entire pre-flight, not just the probe. |
| `--register-only` | GraphQL `bucketAdd` only | Accurate but reads as a verb-mode rather than a skip flag; less obviously paired with `--no-test`. |
| `--via-stack` | Delegate to stack | Indirect; doesn't name the thing being skipped. |
| `--no-setup` | Skip owner setup | Vague — "setup" overloaded across the CLI. |

`--no-preflight` is symmetric with the existing `--no-test`
(skip post-add verification) in `quiltx bucket add`: one skips pre-add work,
the other skips post-add work.

## (a) Where the flag must be available as an option

### CLI surfaces

- [ ] [`quiltx bucket add`](../quiltx/tools/bucket.py#L33-L72) — primary user
      of the local setup routine; flag must be acceptable here.
- [ ] [`quiltx catalog acl`](../quiltx/tools/catalog/acl.py#L13-L43) — the ACL
      reconciler registers buckets indirectly via
      [`_register_bucket_with_retry`](../quiltx/acl.py#L500-L537);
      flag applies to *every* bucket that needs adding during this run.
- [ ] [`quiltx bucket test`](../quiltx/tools/bucket.py#L118-L124) — exempt:
      this command is the explicit post-add verification path, so accepting
      a flag that skips preflight would be misleading and has no useful
      behavior.
- [ ] [`quiltx bucket profile`](../quiltx/tools/bucket.py#L105-L116) — exempt:
      this command exists to *find* a probe-capable profile, so
      `--no-preflight` is nonsensical here.

### Non-CLI affordances

- [ ] **Environment variable** — `QUILTX_NO_PREFLIGHT=1` is the current
      global override for CI / `uvx` contexts where adding the flag to every
      invocation is awkward.
- [ ] **ACL YAML — per-bucket opt-in** *(future, out of scope for this
      change but called out so the flag name doesn't paint us in)*: a
      bucket-level marker in the policies-only ACL YAML, e.g. an entry under
      `buckets.read` that carries a `no-preflight: true` annotation, so a
      single `quiltx catalog acl` run can register some buckets with owner
      setup and others without.

### Interaction with existing flags

- [ ] **`--no-test`** (`bucket add` only) — `--no-preflight` implies
      `--no-test`, because post-add verification is another stack/access
      probe that can fail for the same reason. Users can run
      `quiltx bucket test` later when they explicitly want that check.
- [ ] **`--force`** (`bucket add`) — `--force` removes + re-adds. With
      `--no-preflight`, removal still goes via GraphQL; the re-add must
      also skip preflight. No conflict, but verify the combined behavior.
- [ ] **`--dry-run`** — the dry-run plan must say registration will be
      GraphQL-only and list the skipped local steps: bucket-location probe,
      bucket-policy read/write, SNS setup, bucket-notification config, and
      post-add verification.
- [ ] **`--no-prompt`** — independent; `--no-preflight` should not need or
      trigger prompts in any case.

## (b) Where it must be implemented and tested

### Library-level entry points

- [ ] [`quiltx/bucket.py`](../quiltx/bucket.py) — keep
      `resolve_bucket_session`, `find_profile_for_bucket`, `get_bucket_policy`,
      `apply_bucket_policy`, `ensure_sns_topic`, `configure_sns_topic_policy`,
      `configure_bucket_notifications` for the owner path. Add a new
      sibling helper that performs only the GraphQL `bucketAdd` and maps
      its union-type result to a structured return value. Both paths feed
      the same downstream consumers.
- [ ] [`quiltx/acl.py:_register_bucket_with_retry`](../quiltx/acl.py#L500-L537)
      — route through the new helper when the caller passed
      `no_preflight=True`. Skip steps 1–5 (probe → policy merge → SNS
      plumbing) and call the GraphQL helper directly.

### CLI plumbing

- [ ] [`quiltx/tools/bucket.py`](../quiltx/tools/bucket.py) — add
      `--no-preflight` to the `add` subparser (next to `--no-test` for
      symmetry), thread it into `_cmd_add`, then into the library entry
      point.
- [ ] [`quiltx/tools/catalog/acl.py`](../quiltx/tools/catalog/acl.py) — add
      `--no-preflight` to the `acl` parser, thread into `_run`, then down
      to every `_register_bucket_with_retry` call site.
- [ ] **Env-var resolution** — wherever the CLI converts argparse args to
      booleans, fall back to `os.environ["QUILTX_NO_PREFLIGHT"]` when the
      flag was not passed explicitly.

### Error mapping (the substantive new logic)

The GraphQL `bucketAdd` returns a union — when we no longer probe locally,
these become the *only* signal that something is wrong. Each must produce a
human-readable error on stderr:

- [ ] `BucketAddSuccess` — happy path, registered.
- [ ] `BucketAlreadyAdded` — no-op (currently surfaced as "already registered").
- [ ] `BucketDoesNotExist` — stack cannot reach bucket. Surface explicitly:
      "The stack cannot access this bucket; check the stack's IAM role or
      the bucket's public-access settings."
- [ ] `InsufficientPermissions` — stack reached the bucket but lacks
      necessary actions. Surface the actions needed.
- [ ] `NotificationConfigurationError`, `NotificationTopicNotFound`,
      `SnsInvalid`, `SubscriptionInvalid` — only relevant if an SNS ARN is
      passed; under `--no-preflight` we omit the SNS ARN so these should
      not occur. If they do, surface verbatim.
- [ ] `BucketFileExtensionsToIndexInvalid`, `BucketIndexContentBytesInvalid`
      — input-validation errors; surface verbatim.

### Tests

- [ ] [`tests/test_bucket.py`](../tests/test_bucket.py) —
  - `bucket add --no-preflight` happy path (mocked GraphQL returns
    `BucketAddSuccess`); verify no boto3 S3/SNS calls were made.
  - Each non-success union variant maps to a distinct stderr message
    and non-zero exit code.
  - `--no-preflight` combined with `--no-test` (no-op overlap).
  - `--no-preflight` combined with `--force` (remove + re-add, both via
    GraphQL).
  - `QUILTX_NO_PREFLIGHT=1` env var triggers the same path without the flag.
- [ ] [`tests/test_acl.py`](../tests/test_acl.py) —
  - `catalog acl <file> --no-preflight` registers all new buckets via the
    GraphQL-only path; no boto3 calls.
  - Drift detection still works when some buckets are owner-set-up and
    others are no-preflight (registration mode is local, not a server-side
    property).
  - Failure of one bucket's no-preflight add (e.g. `BucketDoesNotExist`)
    does not roll back successfully-added buckets.

### Documentation

- [ ] [`README.md`](../README.md) — `## Bucket registration` section: when
      to use `--no-preflight` (public Open Data buckets; buckets already
      plumbed in the central account; quick read-only registrations).
- [ ] [`README_DEV.md`](../README_DEV.md) — design notes: why two paths
      exist, when each is appropriate, what guarantees each makes.
- [ ] [`CHANGELOG.md`](../CHANGELOG.md) — entry under the next version.
- [ ] [`AGENTS.md`](../AGENTS.md) — if it lists user-facing flags, update.

## Decisions to lock in before implementation

- [x] `--no-preflight` implies `--no-test`.
- [x] `quiltx bucket test` does not accept `--no-preflight`.
- [x] `QUILTX_NO_PREFLIGHT=1` is the current global override; per-bucket
      YAML opt-in remains future/out of scope.
- [x] Dry-run output shows the skipped local steps; normal output states
      that registration used the GraphQL-only admin-UI path.
