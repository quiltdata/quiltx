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

Use repeatable `--principal arn:aws:iam::123456789012:role/...` options to grant
specific Quilt roles instead of the control-account root. If you don't know the
control account ID, pass `--catalog example.quiltdata.com` instead: any
logged-in catalog user (no admin role needed) can derive it from the catalog's
minted credentials. `--dry-run` prints the
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
with its IAM, skips local S3/SNS setup, and implies `--no-test`. Set
`QUILTX_NO_PREFLIGHT=1` to use the same mode for scripted runs.

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

### Usage

With no config file, the command reports the complete server ACL state, including
users and their active and extra role assignments. Pass `--json` for a complete
machine-readable reporting export, or `--yaml` for a replayable ACL config that
can be saved and passed back to `catalog acl --dry-run`.

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
