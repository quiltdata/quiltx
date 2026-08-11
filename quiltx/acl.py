"""Declarative ACL reconciliation for Quilt stacks."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from quilt3.admin.types import Permission
from quiltx import stack as stack_lib

INLINE_POLICY_SUFFIX = "__inline"
ACL_TOP_LEVEL_KEYS = {"policies", "roles"}
ACL_ENTRY_KEYS = {
    "buckets.read",
    "buckets.read_write",
    "config.default_role",
    "config.is_admin",
}
POLICY_ROLE_NAME_KEY = "name"
CONFIG_POLICIES_KEY = "config.policies"
EVERYONE_GROUP = "Everyone"
REGISTRY_MANAGED_POLICY_EXCLUSIONS = frozenset({"CanaryBucketAccess"})
REGISTRY_MANAGED_ROLE_EXCLUSIONS = frozenset({"Canary"})


@dataclass(frozen=True)
class AclPolicy:
    name: str
    sso: dict[str, list[str]] = field(default_factory=dict)
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    default_role: bool = False
    is_admin: bool | None = None
    role_name: str | None = None


@dataclass(frozen=True)
class AclStaticRole:
    name: str
    sso: dict[str, list[str]] = field(default_factory=dict)
    policies: list[str] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    default_role: bool = False
    is_admin: bool = False


@dataclass(frozen=True)
class AclConfig:
    policies: list[AclPolicy]
    roles: dict[str, AclStaticRole]


@dataclass(frozen=True)
class CurrentState:
    buckets: dict[str, Any]
    managed_policies: dict[str, Any]
    unmanaged_policies: dict[str, Any]
    all_policies: dict[str, Any]
    managed_roles: dict[str, Any]
    unmanaged_roles: dict[str, Any]
    all_roles: dict[str, Any]
    sso_config_text: str | None
    default_role_name: str | None
    users: list[Any] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyUpdate:
    title: str
    permissions: list[Permission]


@dataclass(frozen=True)
class RoleUpdate:
    name: str
    policy_titles: list[str]


@dataclass
class AclDiff:
    buckets_to_add: list[str] = field(default_factory=list)
    policies_to_create: list[PolicyUpdate] = field(default_factory=list)
    policies_to_update: list[PolicyUpdate] = field(default_factory=list)
    policies_to_delete: list[str] = field(default_factory=list)
    roles_to_create: list[RoleUpdate] = field(default_factory=list)
    roles_to_update: list[RoleUpdate] = field(default_factory=list)
    roles_to_delete: list[str] = field(default_factory=list)
    sso_config_text: str | None = None
    sso_is_create: bool = False
    sso_needs_update: bool = False
    warnings: list[str] = field(default_factory=list)

    def has_changes(self) -> bool:
        return any(
            (
                self.buckets_to_add,
                self.policies_to_create,
                self.policies_to_update,
                self.policies_to_delete,
                self.roles_to_create,
                self.roles_to_update,
                self.roles_to_delete,
                self.sso_needs_update,
            )
        )


@dataclass(frozen=True)
class _SynthesizedRole:
    name: str
    sso: dict[str, list[str]]
    policy_titles: list[str]
    source_policies: list[str]
    is_admin: bool | None


@dataclass(frozen=True)
class _ResolvedStaticRole:
    name: str
    sso: dict[str, list[str]]
    policy_titles: list[str]
    is_admin: bool
    default_role: bool
    inline_policy_title: str | None


@dataclass(frozen=True)
class _SsoMapping:
    claim: str
    value: str
    role_name: str
    admin: bool | None = None


@dataclass(frozen=True)
class _ParsedAclEntry:
    sso: dict[str, list[str]]
    read: list[str]
    read_write: list[str]
    default_role: bool
    is_admin: bool | None


@dataclass(frozen=True)
class _DesiredAclState:
    policy_updates: dict[str, PolicyUpdate]
    synthesized_roles: list[_SynthesizedRole]
    static_roles: list[_ResolvedStaticRole]
    role_updates: dict[str, RoleUpdate]
    sso_mappings: list[_SsoMapping]
    default_role_name: str | None
    warnings: list[str] = field(default_factory=list)


def format_exception(exc: Exception) -> str:
    """Format an exception, surfacing GraphQL error details when present."""
    base = str(exc) or exc.__class__.__name__
    errors = getattr(exc, "errors", None)
    if not isinstance(errors, list) or not errors:
        return base
    details: list[tuple[str, str]] = []
    for error in errors:
        message = getattr(error, "message", None)
        if not message:
            continue
        path = getattr(error, "path", None)
        rendered = f"{message} (path: {path})" if path else str(message)
        details.append((str(message), rendered))
    if not details:
        return base
    if all(message == base for message, _rendered in details):
        return "; ".join(rendered for _message, rendered in details)
    return f"{base}: {'; '.join(rendered for _message, rendered in details)}"


def parse_acl_config(path: str | Path) -> AclConfig:
    """Load and validate ACL configuration from YAML."""
    raw = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError("ACL config must be a mapping at the top level")

    _validate_top_level_keys(raw)

    raw_policies = raw.get("policies") or {}
    raw_roles = raw.get("roles") or {}

    if not isinstance(raw_policies, dict):
        raise ValueError("'policies' must be a mapping")
    if not isinstance(raw_roles, dict):
        raise ValueError("'roles' must be a mapping")

    policies: list[AclPolicy] = []
    policy_names: set[str] = set()
    default_role_sources: list[str] = []
    for name, value in raw_policies.items():
        if not isinstance(name, str):
            raise ValueError("Policy names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Policy '{name}' must be a mapping")
        _validate_acl_entry_keys(value, section="policies", name=name)
        if name.endswith(INLINE_POLICY_SUFFIX):
            raise ValueError(
                "Policy names may not end with "
                f"'{INLINE_POLICY_SUFFIX}'; that suffix is reserved for generated "
                "inline-role policies"
            )
        entry = _parse_acl_entry(value, f"policies.{name}")
        role_name = value.get(POLICY_ROLE_NAME_KEY)
        if role_name is not None:
            if not isinstance(role_name, str) or not role_name.strip():
                raise ValueError(f"policies.{name}.name must be a non-empty string")
            role_name = role_name.strip()
        policy = AclPolicy(
            name=name,
            sso=entry.sso,
            read=entry.read,
            read_write=entry.read_write,
            is_admin=entry.is_admin,
            default_role=entry.default_role,
            role_name=role_name,
        )
        policies.append(policy)
        policy_names.add(name)
        if entry.default_role:
            default_role_sources.append(f"policies.{name}")

    roles: dict[str, AclStaticRole] = {}
    role_names: set[str] = set()
    for name, value in raw_roles.items():
        if not isinstance(name, str):
            raise ValueError("Role names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Role '{name}' must be a mapping")
        _validate_acl_entry_keys(value, section="roles", name=name)
        reserved_inline_policy = f"{name}{INLINE_POLICY_SUFFIX}"
        if reserved_inline_policy in raw_policies:
            raise ValueError(
                f"Role '{name}' conflicts with reserved generated inline policy "
                f"'{reserved_inline_policy}'"
            )
        entry = _parse_acl_entry(value, f"roles.{name}")
        policy_refs = _coerce_string_list(
            value.get(CONFIG_POLICIES_KEY, []), f"roles.{name}.{CONFIG_POLICIES_KEY}"
        )
        missing = [
            policy_name
            for policy_name in policy_refs
            if policy_name not in policy_names
        ]
        if missing:
            raise ValueError(
                f"Role '{name}' references unknown policies: {', '.join(missing)}"
            )
        roles[name] = AclStaticRole(
            name=name,
            sso=entry.sso,
            policies=_dedupe_preserve_order(policy_refs),
            read=entry.read,
            read_write=entry.read_write,
            default_role=entry.default_role,
            is_admin=bool(entry.is_admin),
        )
        role_names.add(name)
        if entry.default_role:
            default_role_sources.append(f"roles.{name}")

    if len(default_role_sources) > 1:
        raise ValueError(
            "Only one ACL entry may set config.default_role: true; found "
            + ", ".join(default_role_sources)
        )

    _validate_policy_ladder(policies)
    _validate_synthetic_role_names(policies, role_names)

    return AclConfig(
        policies=policies,
        roles=roles,
    )


def all_buckets(config: AclConfig) -> set[str]:
    """Return all buckets referenced by the ACL config."""
    result: set[str] = set()
    for policy in config.policies:
        result.update(policy.read)
        result.update(policy.read_write)
    for role in config.roles.values():
        result.update(role.read)
        result.update(role.read_write)
    return result


def fetch_current_state(stack: stack_lib.Catalog) -> CurrentState:
    """Fetch current buckets, policies, roles, and SSO configuration."""
    bucket_items = {bucket.name: bucket for bucket in stack.admin.buckets.list()}

    managed_policies: dict[str, Any] = {}
    unmanaged_policies: dict[str, Any] = {}
    for policy in stack.admin.policies.list():
        if policy.managed:
            managed_policies[policy.title] = policy
        else:
            unmanaged_policies[policy.title] = policy

    managed_roles: dict[str, Any] = {}
    unmanaged_roles: dict[str, Any] = {}
    for role in stack.admin.roles.list():
        typename = getattr(role, "typename__", "")
        if typename == "ManagedRole":
            managed_roles[role.name] = role
        else:
            unmanaged_roles[role.name] = role

    sso_config = stack.admin.sso_config.get()
    default_role = stack.admin.roles.get_default()
    users = list(stack.admin.users.list())
    return CurrentState(
        buckets=bucket_items,
        managed_policies=managed_policies,
        unmanaged_policies=unmanaged_policies,
        all_policies={**unmanaged_policies, **managed_policies},
        managed_roles=managed_roles,
        unmanaged_roles=unmanaged_roles,
        all_roles={**unmanaged_roles, **managed_roles},
        sso_config_text=None if sso_config is None else sso_config.text,
        default_role_name=None if default_role is None else default_role.name,
        users=users,
    )


def compute_diff(desired: AclConfig, current: CurrentState) -> AclDiff:
    """Compute the actions required to reconcile ACL state."""
    desired_state = _build_desired_acl_state(desired)
    diff = AclDiff()
    diff.warnings.extend(desired_state.warnings)
    diff.buckets_to_add = sorted(all_buckets(desired) - current.buckets.keys())

    desired_policy_titles = set(desired_state.policy_updates)
    for title, policy_update in desired_state.policy_updates.items():
        if title in current.unmanaged_policies:
            diff.warnings.append(
                f"Policy '{title}' already exists as unmanaged; skipping managed policy update."
            )
            continue

        current_policy = current.managed_policies.get(title)
        if current_policy is None:
            diff.policies_to_create.append(policy_update)
            continue

        if _canonical_permissions(current_policy.permissions) != _canonical_permissions(
            policy_update.permissions
        ):
            diff.policies_to_update.append(policy_update)

    diff.policies_to_delete = sorted(
        title
        for title in current.managed_policies
        if title not in desired_policy_titles
        and title not in REGISTRY_MANAGED_POLICY_EXCLUSIONS
    )

    desired_role_names = set(desired_state.role_updates)
    for name, role_update in desired_state.role_updates.items():
        if name in current.unmanaged_roles:
            diff.warnings.append(
                f"Role '{name}' already exists as unmanaged; skipping managed role update."
            )
            continue

        current_role = current.managed_roles.get(name)
        desired_policy_titles_for_role = list(role_update.policy_titles)
        if current_role is None:
            diff.roles_to_create.append(
                RoleUpdate(name=name, policy_titles=desired_policy_titles_for_role)
            )
            continue

        current_policy_titles = sorted(policy.title for policy in current_role.policies)
        if current_policy_titles != sorted(desired_policy_titles_for_role):
            diff.roles_to_update.append(
                RoleUpdate(name=name, policy_titles=desired_policy_titles_for_role)
            )

    diff.roles_to_delete = sorted(
        name
        for name in current.managed_roles
        if name not in desired_role_names
        and name not in REGISTRY_MANAGED_ROLE_EXCLUSIONS
    )

    desired_sso_text = build_sso_config(desired)
    if desired_sso_text is not None and not _same_yaml(
        current.sso_config_text, desired_sso_text
    ):
        diff.sso_config_text = desired_sso_text
        diff.sso_is_create = current.sso_config_text is None
        diff.sso_needs_update = True

    return diff


def build_sso_config(config: AclConfig) -> str | None:
    """Translate the flat ACL config into Quilt's schema-based SSO YAML."""
    desired_state = _build_desired_acl_state(config)
    if not desired_state.sso_mappings and desired_state.default_role_name is None:
        return None

    payload: dict[str, Any] = {"version": "1.0", "union_roles": True, "mappings": []}
    if desired_state.default_role_name is not None:
        payload["default_role"] = desired_state.default_role_name

    for mapping in desired_state.sso_mappings:
        entry: dict[str, Any] = {
            "schema": {
                "type": "object",
                "properties": {
                    mapping.claim: _sso_claim_schema(mapping.claim, mapping.value)
                },
                "required": [mapping.claim],
            },
            "roles": [mapping.role_name],
        }
        # Server tri-state: True grants admin, False vetoes, missing = non-vote.
        # Only emit False when the config explicitly requests a veto.
        if mapping.admin is not None:
            entry["admin"] = mapping.admin
        payload["mappings"].append(entry)

    return yaml.safe_dump(payload, sort_keys=False)


def print_diff(
    diff: AclDiff,
    *,
    verbose: bool = False,
    desired: AclConfig | None = None,
    current: CurrentState | None = None,
) -> None:
    """Print a readable summary of ACL changes."""
    if verbose and desired is not None:
        _print_verbose_state(diff, desired, current)
        for warning in diff.warnings:
            print(f"! {warning}")
        if not diff.has_changes() and not diff.warnings:
            print("Stack ACL is up to date")
        return

    for bucket in diff.buckets_to_add:
        print(f"+ bucket {bucket}")

    for policy in diff.policies_to_create:
        print(f"+ policy {policy.title}")
    for policy in diff.policies_to_update:
        print(f"~ policy {policy.title}")
    for title in diff.policies_to_delete:
        print(f"- policy {title}")

    for role in diff.roles_to_create:
        print(f"+ role {role.name}")
    for role in diff.roles_to_update:
        print(f"~ role {role.name}")
    for name in diff.roles_to_delete:
        print(f"- role {name}")

    if diff.sso_needs_update:
        prefix = "+" if diff.sso_is_create else "~"
        print(f"{prefix} sso config")
        if verbose and diff.sso_config_text:
            for line in diff.sso_config_text.rstrip().splitlines():
                print(f"    {line}")

    for warning in diff.warnings:
        print(f"! {warning}")

    if not diff.has_changes() and not diff.warnings:
        print("Stack ACL is up to date")


def print_current_state(current: CurrentState) -> None:
    """Print a human-readable dump of the current server ACL state."""
    for name in sorted(current.buckets):
        print(f"  bucket {name}")

    for title, policy in sorted(current.managed_policies.items()):
        print(f"  policy {title} (managed)")
        _print_permissions(policy.permissions)
    for title, policy in sorted(current.unmanaged_policies.items()):
        print(f"  policy {title} (unmanaged)")
        _print_permissions(policy.permissions)

    for name, role in sorted(current.managed_roles.items()):
        default_tag = " (default)" if name == current.default_role_name else ""
        policy_names = ", ".join(p.title for p in role.policies) or "(none)"
        print(f"  role {name}{default_tag} (managed)")
        print(f"    policies: {policy_names}")
    for name, role in sorted(current.unmanaged_roles.items()):
        default_tag = " (default)" if name == current.default_role_name else ""
        policies = getattr(role, "policies", None)
        policy_names = ", ".join(p.title for p in policies) if policies else "(n/a)"
        print(f"  role {name}{default_tag} (unmanaged)")
        print(f"    policies: {policy_names}")

    for user in sorted(current.users, key=lambda item: item.name):
        primary_role = user.role.name if user.role else "(none)"
        extra_roles = ", ".join(role.name for role in (user.extra_roles or [])) or (
            "(none)"
        )
        print(f"  user {user.name}")
        print(f"    email: {user.email or '(none)'}")
        print(f"    active role: {primary_role}")
        print(f"    extra roles: {extra_roles}")
        print(
            "    flags: "
            f"admin={user.is_admin}, active={user.is_active}, "
            f"sso_only={user.is_sso_only}, service={user.is_service}"
        )
        date_joined = _json_value(user.date_joined)
        last_login = _json_value(user.last_login)
        print(
            f"    date joined: {date_joined if date_joined is not None else '(none)'}"
        )
        print(f"    last login: {last_login if last_login is not None else '(none)'}")

    if current.sso_config_text:
        print("  sso config")
        _print_sso_summary(current.sso_config_text)
    else:
        print("  sso config: (none)")


def current_state_as_dict(
    current: CurrentState, *, catalog: str | None = None
) -> dict[str, Any]:
    """Return the complete current ACL state as JSON-compatible data."""
    payload: dict[str, Any] = {
        "buckets": [
            _bucket_as_dict(bucket) for _name, bucket in sorted(current.buckets.items())
        ],
        "policies": [
            _policy_as_dict(policy, managed=title in current.managed_policies)
            for title, policy in sorted(current.all_policies.items())
        ],
        "roles": [
            _role_as_dict(
                role,
                managed=name in current.managed_roles,
                is_default=name == current.default_role_name,
            )
            for name, role in sorted(current.all_roles.items())
        ],
        "users": [
            _user_as_dict(user) for user in sorted(current.users, key=lambda u: u.name)
        ],
        "sso_config": current.sso_config_text,
        "default_role": current.default_role_name,
    }
    if catalog is not None:
        payload = {"catalog": catalog, **payload}
    return payload


def _bucket_as_dict(bucket: Any) -> dict[str, Any]:
    fields = (
        "name",
        "title",
        "icon_url",
        "description",
        "overview_url",
        "tags",
        "relevance_score",
        "last_indexed",
        "sns_notification_arn",
        "scanner_parallel_shards_depth",
        "skip_meta_data_indexing",
        "file_extensions_to_index",
        "index_content_bytes",
        "prefixes",
    )
    return {
        field_name: _json_value(getattr(bucket, field_name))
        for field_name in fields
        if hasattr(bucket, field_name)
    }


def _policy_as_dict(policy: Any, *, managed: bool) -> dict[str, Any]:
    return {
        "id": _json_value(getattr(policy, "id", None)),
        "title": policy.title,
        "arn": _json_value(getattr(policy, "arn", None)),
        "managed": managed,
        "permissions": [
            {
                "bucket": permission.bucket,
                "level": _json_value(permission.level),
            }
            for permission in (getattr(policy, "permissions", None) or [])
        ],
        "roles": [role.name for role in (getattr(policy, "roles", None) or [])],
    }


def _role_as_dict(role: Any, *, managed: bool, is_default: bool) -> dict[str, Any]:
    policies = getattr(role, "policies", None)
    permissions = getattr(role, "permissions", None)
    return {
        "id": _json_value(getattr(role, "id", None)),
        "name": role.name,
        "arn": _json_value(getattr(role, "arn", None)),
        "managed": managed,
        "default": is_default,
        "policies": None if policies is None else [policy.title for policy in policies],
        "permissions": (
            None
            if permissions is None
            else [
                {
                    "bucket": permission.bucket,
                    "level": _json_value(permission.level),
                }
                for permission in permissions
            ]
        ),
    }


def _user_as_dict(user: Any) -> dict[str, Any]:
    return {
        "name": user.name,
        "email": user.email,
        "role": None if user.role is None else user.role.name,
        "extra_roles": [role.name for role in (user.extra_roles or [])],
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "is_sso_only": user.is_sso_only,
        "is_service": user.is_service,
        "date_joined": _json_value(user.date_joined),
        "last_login": _json_value(user.last_login),
    }


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, (str, int, float, bool)):
        return enum_value
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return isoformat()
    return str(value)


def _register_bucket_with_retry(
    stack: stack_lib.Catalog,
    bucket: str,
    control_account_id: str,
    *,
    assume_yes: bool,
) -> None:
    """Run the full cross-account bucket registration, probing profiles on failure."""
    from quiltx import bucket as bucket_lib

    session, s3_client, region, _profile = bucket_lib.resolve_bucket_session(
        bucket, None, assume_yes=assume_yes
    )
    if session is None:
        raise RuntimeError(f"no accessible AWS profile for bucket {bucket}")

    sns_client = session.client("sns", region_name=region)
    data_account_id = str(session.client("sts").get_caller_identity()["Account"])

    existing_policy = bucket_lib.get_bucket_policy(bucket, s3_client=s3_client)
    statement = bucket_lib.build_quilt_policy_statement(bucket, control_account_id)
    merged = bucket_lib.merge_bucket_policy(existing_policy, statement)
    bucket_lib.apply_bucket_policy(bucket, merged, s3_client=s3_client)

    sns_topic_arn = bucket_lib.get_bucket_notification_sns(bucket, s3_client=s3_client)
    if sns_topic_arn is None:
        sns_topic_arn = bucket_lib.ensure_sns_topic(
            bucket, region, sns_client=sns_client
        )
    bucket_lib.configure_sns_topic_policy(
        bucket,
        sns_topic_arn,
        data_account_id,
        f"arn:aws:iam::{control_account_id}:root",
        sns_client=sns_client,
    )
    bucket_lib.configure_bucket_notifications(
        bucket, sns_topic_arn, s3_client=s3_client
    )
    stack.admin.buckets.add(
        name=bucket, title=bucket, sns_notification_arn=sns_topic_arn
    )


def _prune_sso_config_for_missing_roles(
    config_text: str, available_roles: set[str]
) -> tuple[str | None, set[str]]:
    """Drop SSO mappings (and default_role) that reference unavailable roles.

    The registry rejects the whole SSO config with RolesNotFound when even one
    referenced role is missing. Pruning lets us still apply the mappings whose
    roles do exist server-side. Returns ``(pruned_yaml, dropped_role_names)``;
    pruned_yaml is None when nothing meaningful is left to apply.

    The registry's SsoConfig schema makes ``default_role`` a required field
    (pydantic, no default). If pruning would leave the payload without a
    ``default_role`` we cannot send it — the registry would reject with
    ``InvalidInput: config.default_role: field required``. In that case we
    return None so the caller skips the SSO update; the mappings will land
    on the next apply once the missing role exists.
    """
    payload = yaml.safe_load(config_text)
    if not isinstance(payload, dict):
        return config_text, set()

    dropped: set[str] = set()
    pruned_mappings: list[Any] = []
    for entry in payload.get("mappings") or []:
        roles = entry.get("roles") or []
        surviving = [r for r in roles if r in available_roles]
        missing = [r for r in roles if r not in available_roles]
        dropped.update(missing)
        if not surviving:
            # All roles in this mapping are missing; drop the whole entry.
            continue
        if missing:
            # Keep the entry with the surviving roles so the SSO grant for
            # those still applies. (Today's tooling emits single-role
            # entries, but multi-role entries are valid in the schema.)
            new_entry = dict(entry)
            new_entry["roles"] = surviving
            pruned_mappings.append(new_entry)
        else:
            pruned_mappings.append(entry)
    payload["mappings"] = pruned_mappings

    default_role = payload.get("default_role")
    default_role_dropped = False
    if default_role and default_role not in available_roles:
        dropped.add(default_role)
        payload.pop("default_role", None)
        default_role_dropped = True

    if default_role_dropped:
        # Registry's SsoConfig schema requires default_role; sending the
        # payload without it fails pydantic validation
        # (`config.default_role: field required`) before any DB write. Skip
        # entirely; mappings land on a later apply once the role exists.
        return None, dropped

    if not pruned_mappings and "default_role" not in payload:
        return None, dropped

    return yaml.safe_dump(payload, sort_keys=False), dropped


def apply_acl(
    stack: stack_lib.Catalog,
    diff: AclDiff,
    current: CurrentState,
    *,
    verbose: bool = False,
    assume_yes: bool = False,
    no_preflight: bool = False,
) -> list[str]:
    """Apply ACL changes. Returns any runtime warnings."""

    warnings = list(diff.warnings)
    failed_buckets: set[str] = set()
    failed_roles: set[str] = set()

    control_account_id: str | None = None
    if diff.buckets_to_add:
        try:
            payload = stack.payload
            if payload and payload.get("account_id"):
                control_account_id = str(payload["account_id"])
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(f"Could not load control account for bucket add: {exc}")

    for bucket in diff.buckets_to_add:
        try:
            _print_apply_step(f"add bucket {bucket}", verbose=verbose)
            if no_preflight:
                from quiltx import bucket as bucket_lib

                bucket_lib.add_bucket_without_preflight(stack, bucket, title=bucket)
            elif control_account_id is None:
                stack.admin.buckets.add(bucket, bucket)
            else:
                _register_bucket_with_retry(
                    stack,
                    bucket,
                    control_account_id,
                    assume_yes=assume_yes,
                )
            print(f"  + bucket {bucket}")
        except Exception as exc:
            failed_buckets.add(bucket)
            warnings.append(f"Bucket '{bucket}' could not be added: {exc}")
            print(f"  ! bucket {bucket}: {exc}", file=sys.stderr)

    known_policies = dict(current.all_policies)
    for policy in diff.policies_to_create:
        _print_apply_step(f"create policy {policy.title}", verbose=verbose)
        affected = _policy_uses_buckets(policy.permissions, failed_buckets)
        try:
            created = stack.admin.policies.create_managed(
                policy.title, permissions=policy.permissions
            )
        except Exception as exc:
            hint = (
                f" (references failed buckets: {', '.join(sorted(affected))})"
                if affected
                else ""
            )
            detail = format_exception(exc)
            if _is_internal_server_error(detail):
                desired = _format_permissions(policy.permissions)
                server_state = _describe_policy_state(stack, policy.title)
                suffix = f" [desired: [{desired}]; {server_state}]"
            else:
                suffix = ""
            warnings.append(
                f"Policy '{policy.title}' could not be created{hint}: {detail}{suffix}"
            )
            print(
                f"  ! policy {policy.title}: {detail}{suffix}",
                file=sys.stderr,
            )
            continue
        known_policies[policy.title] = created
        print(f"  + policy {policy.title}")
        dropped = _dropped_permissions(policy.permissions, created.permissions)
        if dropped:
            detail = (
                f"server accepted create but dropped permissions: {', '.join(dropped)}"
            )
            warnings.append(f"Policy '{policy.title}' {detail}")
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)
    for policy in diff.policies_to_update:
        _print_apply_step(f"update policy {policy.title}", verbose=verbose)
        affected = _policy_uses_buckets(policy.permissions, failed_buckets)
        # Resolve by id when possible — quilt3's update_managed(title) first
        # calls _get_by_id which currently 500s on non-UUID inputs instead of
        # returning None, so the title fallback never runs.
        existing = known_policies.get(policy.title)
        policy_ref = existing.id if existing is not None else policy.title
        existing_role_ids = (
            [role.id for role in getattr(existing, "roles", []) or []]
            if existing is not None
            else []
        )
        try:
            updated = stack.admin.policies.update_managed(
                policy_ref,
                title=policy.title,
                permissions=policy.permissions,
                roles=existing_role_ids,
            )
        except Exception as exc:
            hint = (
                f" (references failed buckets: {', '.join(sorted(affected))})"
                if affected
                else ""
            )
            detail = format_exception(exc)
            if _is_internal_server_error(detail):
                desired = _format_permissions(policy.permissions)
                server_state = _describe_policy_state(stack, policy.title)
                suffix = f" [desired: [{desired}]; {server_state}]"
            else:
                suffix = ""
            warnings.append(
                f"Policy '{policy.title}' could not be updated{hint}: {detail}{suffix}"
            )
            print(
                f"  ! policy {policy.title}: {detail}{suffix}",
                file=sys.stderr,
            )
            continue
        known_policies[policy.title] = updated
        print(f"  ~ policy {policy.title}")
        dropped = _dropped_permissions(policy.permissions, updated.permissions)
        if dropped:
            detail = (
                f"server accepted update but dropped permissions: {', '.join(dropped)}"
            )
            warnings.append(f"Policy '{policy.title}' {detail}")
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)

    for role in diff.roles_to_create:
        _print_apply_step(f"create role {role.name}", verbose=verbose)
        try:
            policy_ids = _resolve_policy_ids(role.policy_titles, known_policies)
            stack.admin.roles.create_managed(role.name, policies=policy_ids)
        except KeyError as exc:
            warnings.append(
                f"Role '{role.name}' skipped: unknown policy {exc.args[0]!r}"
            )
            print(
                f"  ! role {role.name}: unknown policy {exc.args[0]!r}", file=sys.stderr
            )
            failed_roles.add(role.name)
            continue
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"Role '{role.name}' could not be created: {detail}")
            print(f"  ! role {role.name}: {detail}", file=sys.stderr)
            failed_roles.add(role.name)
            continue
        print(f"  + role {role.name}")

    for role in diff.roles_to_update:
        _print_apply_step(f"update role {role.name}", verbose=verbose)
        try:
            policy_ids = _resolve_policy_ids(role.policy_titles, known_policies)
            existing = current.managed_roles.get(role.name)
            role_ref = existing.id if existing is not None else role.name
            stack.admin.roles.update_managed(
                role_ref, name=role.name, policies=policy_ids
            )
        except KeyError as exc:
            warnings.append(
                f"Role '{role.name}' skipped: unknown policy {exc.args[0]!r}"
            )
            print(
                f"  ! role {role.name}: unknown policy {exc.args[0]!r}", file=sys.stderr
            )
            continue
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"Role '{role.name}' could not be updated: {detail}")
            print(f"  ! role {role.name}: {detail}", file=sys.stderr)
            continue
        print(f"  ~ role {role.name}")

    sso_text_to_restore = current.sso_config_text
    if diff.sso_needs_update and diff.sso_config_text is not None:
        _print_apply_step("update sso config", verbose=verbose)
        # Failed roles would make the registry reject the entire SSO config
        # with RolesNotFound — prune those mappings (and default_role) so the
        # roles that DID land still take effect, instead of losing all SSO.
        available_roles = set(current.all_roles.keys()) | (
            {role.name for role in diff.roles_to_create} - failed_roles
        )
        pruned_text, dropped_roles = _prune_sso_config_for_missing_roles(
            diff.sso_config_text, available_roles
        )
        if pruned_text is None:
            roles_part = (
                f" (missing roles: {', '.join(sorted(dropped_roles))})"
                if dropped_roles
                else ""
            )
            warnings.append(
                "SSO config not updated: pruning would leave the payload "
                "without a default_role (or with no surviving mappings); "
                "the registry requires default_role to be present. "
                f"Re-run after the missing role(s) are created.{roles_part}"
            )
            print(
                "  ! sso config: skipped (default_role or all mappings dropped)",
                file=sys.stderr,
            )
        else:
            if dropped_roles:
                warnings.append(
                    f"SSO config pruned to skip missing roles: "
                    f"{', '.join(sorted(dropped_roles))}. Mappings referencing "
                    f"them were dropped so the rest of SSO still applies."
                )
                print(
                    f"  ~ sso config: pruned roles {', '.join(sorted(dropped_roles))}",
                    file=sys.stderr,
                )
            try:
                stack.admin.sso_config.set(pruned_text)
            except Exception as exc:
                detail = format_exception(exc)
                warnings.append(f"SSO config could not be updated: {detail}")
                print(f"  ! sso config: {detail}", file=sys.stderr)
            else:
                sso_text_to_restore = pruned_text
                prefix = "+" if diff.sso_is_create else "~"
                print(f"  {prefix} sso config")

    sso_cleared_for_role_delete = False
    roles_to_delete = set(diff.roles_to_delete)
    if roles_to_delete:
        try:
            users_to_detach = users_assigned_to_roles(stack, roles_to_delete)
        except Exception as exc:  # pragma: no cover - external API surface
            detail = format_exception(exc)
            warnings.append(f"Users could not be checked before role delete: {detail}")
            users_to_detach = []
        if users_to_detach:
            warnings.extend(clear_sso_config(stack, verbose=verbose))
            sso_cleared_for_role_delete = True
        else:
            try:
                sso_detach_warnings = detach_sso_mappings_for_roles(
                    stack, roles_to_delete, verbose=verbose
                )
            except Exception as exc:  # pragma: no cover - external API surface
                warnings.append(
                    "SSO mappings could not be checked before role delete: "
                    f"{format_exception(exc)}"
                )
            else:
                warnings.extend(sso_detach_warnings)

    for role_name in diff.roles_to_delete:
        try:
            detach_warnings, _snapshot = detach_users_from_role(
                stack, role_name, verbose=verbose
            )
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(
                f"Users could not be detached before deleting role "
                f"'{role_name}': {format_exception(exc)}"
            )
        else:
            warnings.extend(detach_warnings)
        warnings.extend(
            detach_all_policies_from_roles(
                stack,
                {role_name},
                current,
                known_policies,
                verbose=verbose,
            )
        )
        try:
            role_ref = _role_ref(role_name, current)
            _print_apply_step(f"delete role {role_name}", verbose=verbose)
            stack.admin.roles.delete(role_ref)
            print(f"  - role {role_name}")
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(
                f"Role '{role_name}' could not be deleted: {format_exception(exc)}"
            )

    if sso_cleared_for_role_delete and sso_text_to_restore is not None:
        _print_apply_step("restore sso config", verbose=verbose)
        try:
            stack.admin.sso_config.set(sso_text_to_restore)
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"SSO config could not be restored: {detail}")
            print(f"  ! sso config: {detail}", file=sys.stderr)
        else:
            print("  ~ sso config (restored)")
    elif sso_cleared_for_role_delete:
        warnings.append(
            "SSO config was cleared for role deletion and no SSO config text "
            "was available to restore."
        )
        print("  ! sso config: no restore payload available", file=sys.stderr)

    warnings.extend(
        detach_policies_from_roles(
            stack,
            set(diff.policies_to_delete),
            current,
            known_policies,
            roles_to_delete=roles_to_delete,
            verbose=verbose,
        )
    )

    for policy_title in diff.policies_to_delete:
        try:
            policy_ref = _policy_ref(policy_title, current)
            _print_apply_step(f"delete policy {policy_title}", verbose=verbose)
            stack.admin.policies.delete(policy_ref)
            print(f"  - policy {policy_title}")
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(
                f"Policy '{policy_title}' could not be deleted: {format_exception(exc)}"
            )

    return warnings


@dataclass(frozen=True)
class PolicyDrift:
    """A managed policy whose server state diverges from the desired state."""

    title: str
    desired: list[Permission]
    actual: list[Permission]

    @property
    def missing(self) -> list[str]:
        desired = _canonical_permissions(self.desired)
        actual = set(_canonical_permissions(self.actual))
        return [
            f"{level.split('.')[-1]}:{bucket}"
            for bucket, level in desired
            if (bucket, level) not in actual
        ]

    @property
    def extra(self) -> list[str]:
        actual = _canonical_permissions(self.actual)
        desired = set(_canonical_permissions(self.desired))
        return [
            f"{level.split('.')[-1]}:{bucket}"
            for bucket, level in actual
            if (bucket, level) not in desired
        ]


def detect_policy_drift(desired: AclConfig, current: CurrentState) -> list[PolicyDrift]:
    """Return managed policies where the server state diverges from desired.

    Detection is always-on: the catalog's policyUpdateManaged mutation has
    historically both silently dropped permissions and returned 500 while
    partially persisting. This compares the desired permissions for each
    managed policy against whatever the server currently holds.
    """
    desired_state = _build_desired_acl_state(desired)
    drift: list[PolicyDrift] = []
    for title, policy_update in desired_state.policy_updates.items():
        current_policy = current.managed_policies.get(title)
        actual_permissions = (
            list(current_policy.permissions) if current_policy is not None else []
        )
        if current_policy is not None and _canonical_permissions(
            current_policy.permissions
        ) == _canonical_permissions(policy_update.permissions):
            continue
        drift.append(
            PolicyDrift(
                title=title,
                desired=list(policy_update.permissions),
                actual=actual_permissions,
            )
        )
    return drift


def managed_roles_using_policy(policy_title: str, current: CurrentState) -> list[str]:
    """Return managed role names that reference the given policy."""
    return sorted(
        name
        for name, role in current.managed_roles.items()
        if any(p.title == policy_title for p in getattr(role, "policies", []) or [])
    )


def _role_ref(role_name: str, current: CurrentState) -> str:
    role = current.all_roles.get(role_name)
    return str(role.id) if role is not None else role_name


def _policy_ref(policy_title: str, current: CurrentState) -> str:
    policy = current.all_policies.get(policy_title)
    return str(policy.id) if policy is not None else policy_title


def detach_all_policies_from_roles(
    stack: stack_lib.Catalog,
    role_names: set[str],
    current: CurrentState,
    known_policies: dict[str, Any],
    *,
    verbose: bool = False,
) -> list[str]:
    """Remove all policy associations from roles before deleting those roles."""
    warnings: list[str] = []
    for role_name in sorted(role_names):
        role = current.managed_roles.get(role_name)
        if role is None:
            continue
        current_policies = list(getattr(role, "policies", []) or [])
        if not current_policies:
            continue
        try:
            _print_apply_step(f"detach policies from role {role_name}", verbose=verbose)
            stack.admin.roles.update_managed(role.id, name=role_name, policies=[])
            print(f"  ~ role {role_name} (detached policies)")
        except Exception as exc:
            detail = format_exception(exc)
            fallback_warnings = detach_role_from_policies_via_policy_updates(
                stack,
                role_name,
                current_policies,
                current,
                known_policies,
                verbose=verbose,
            )
            if fallback_warnings:
                warnings.append(
                    f"Role '{role_name}' could not be detached from policies "
                    f"before delete: {detail}"
                )
                warnings.extend(fallback_warnings)
                print(f"  ! role {role_name}: {detail}", file=sys.stderr)
    return warnings


def detach_role_from_policies_via_policy_updates(
    stack: stack_lib.Catalog,
    role_name: str,
    current_policies: list[Any],
    current: CurrentState,
    known_policies: dict[str, Any],
    *,
    verbose: bool = False,
) -> list[str]:
    """Remove a role association by rewriting each attached policy's role list."""
    warnings: list[str] = []
    role = current.managed_roles.get(role_name)
    if role is None:
        return warnings

    for policy_summary in current_policies:
        policy = known_policies.get(policy_summary.title)
        if policy is None:
            policy = current.managed_policies.get(policy_summary.title)
        if policy is None:
            warnings.append(
                f"Policy '{policy_summary.title}' could not be used to detach "
                f"role '{role_name}': policy not found in current state"
            )
            continue

        remaining_role_ids = [
            r.id
            for r in getattr(policy, "roles", []) or []
            if getattr(r, "name", None) != role_name
            and getattr(r, "id", None) != role.id
        ]
        try:
            _print_apply_step(
                f"detach role {role_name} from policy {policy.title}",
                verbose=verbose,
            )
            stack.admin.policies.update_managed(
                policy.id,
                title=policy.title,
                permissions=list(getattr(policy, "permissions", []) or []),
                roles=remaining_role_ids,
            )
            print(f"  ~ policy {policy.title} (detached role {role_name})")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(
                f"Policy '{policy.title}' could not detach role "
                f"'{role_name}': {detail}"
            )
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)

    return warnings


def detach_policies_from_roles(
    stack: stack_lib.Catalog,
    policy_titles: set[str],
    current: CurrentState,
    known_policies: dict[str, Any],
    *,
    roles_to_delete: set[str],
    verbose: bool = False,
) -> list[str]:
    """Remove retiring policies from surviving managed roles before policy delete."""
    warnings: list[str] = []
    if not policy_titles:
        return warnings

    for role_name, role in sorted(current.managed_roles.items()):
        if role_name in roles_to_delete:
            continue
        current_policies = list(getattr(role, "policies", []) or [])
        if not any(policy.title in policy_titles for policy in current_policies):
            continue

        surviving_policy_ids: list[str] = []
        for policy in current_policies:
            if policy.title in policy_titles:
                continue
            known = known_policies.get(policy.title)
            surviving_policy_ids.append(
                str(known.id if known is not None else policy.id)
            )

        try:
            _print_apply_step(f"detach policies from role {role_name}", verbose=verbose)
            stack.admin.roles.update_managed(
                role.id,
                name=role_name,
                policies=surviving_policy_ids,
            )
            print(f"  ~ role {role_name} (detached deleted policies)")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(
                f"Role '{role_name}' could not be detached from deleted "
                f"policies {', '.join(sorted(policy_titles))}: {detail}"
            )
            print(f"  ! role {role_name}: {detail}", file=sys.stderr)

    return warnings


def detach_sso_mappings_for_roles(
    stack: stack_lib.Catalog, role_names: set[str], *, verbose: bool = False
) -> list[str]:
    """Rewrite the live SSO config so it no longer references the given roles.

    The registry rejects roleDeleteManaged while a role is still bound in the
    SSO mapping, so callers that need to delete synthetic roles must clear
    the mapping first. The recreate-and-reapply flow restores the mappings
    when the new role IDs exist.
    """
    warnings: list[str] = []
    current_sso = stack.admin.sso_config.get()
    if current_sso is None or not current_sso.text:
        return warnings
    try:
        payload = yaml.safe_load(current_sso.text) or {}
    except yaml.YAMLError as exc:
        warnings.append(f"SSO config YAML could not be parsed: {exc}")
        return warnings
    if not isinstance(payload, dict):
        return warnings

    mappings = payload.get("mappings") or []
    new_mappings: list[Any] = []
    changed = False
    for mapping in mappings:
        if not isinstance(mapping, dict):
            new_mappings.append(mapping)
            continue
        roles = mapping.get("roles") or []
        remaining = [r for r in roles if r not in role_names]
        if remaining != roles:
            changed = True
            if not remaining:
                continue
            mapping = {**mapping, "roles": remaining}
        new_mappings.append(mapping)

    if payload.get("default_role") in role_names:
        payload.pop("default_role", None)
        changed = True

    if not changed:
        return warnings

    payload["mappings"] = new_mappings
    new_text = yaml.safe_dump(payload, sort_keys=False)
    _print_apply_step(
        f"detach sso mappings for {', '.join(sorted(role_names))}", verbose=verbose
    )
    try:
        stack.admin.sso_config.set(new_text)
        print(f"  ~ sso config (detached: {', '.join(sorted(role_names))})")
    except Exception as exc:
        detail = format_exception(exc)
        warnings.append(f"SSO config could not be detached: {detail}")
        print(f"  ! sso config: {detail}", file=sys.stderr)
    return warnings


@dataclass(frozen=True)
class UserRoleBinding:
    """Snapshot of a user's role assignments for restore after role recreate."""

    user_name: str
    primary: str | None
    extras: list[str]


def detach_users_from_role(
    stack: stack_lib.Catalog, role_name: str, *, verbose: bool = False
) -> tuple[list[str], list[UserRoleBinding]]:
    """Remove a role from every user that has it assigned.

    The registry rejects roleDeleteManaged while a user still has the role
    as their primary or extra role. Returns (warnings, snapshot) where
    snapshot lets callers restore the original assignments once the role
    has been recreated.
    """
    warnings: list[str] = []
    snapshot: list[UserRoleBinding] = []
    fallback_name: str | None = None
    fallback_loaded = False
    for user in stack.admin.users.list():
        primary = user.role.name if user.role else None
        extras = [
            r.name for r in (getattr(user, "extra_roles", None) or []) if r is not None
        ]
        if primary != role_name and role_name not in extras:
            continue
        if not fallback_loaded:
            default_role = stack.admin.roles.get_default()
            fallback_name = default_role.name if default_role is not None else None
            fallback_loaded = True
        snapshot.append(
            UserRoleBinding(user_name=user.name, primary=primary, extras=extras)
        )
        _print_apply_step(
            f"detach user {user.name} from role {role_name}", verbose=verbose
        )
        try:
            stack.admin.users.remove_roles(
                user.name, [role_name], fallback=fallback_name
            )
            print(f"  ~ user {user.name} (detached {role_name})")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(
                f"User '{user.name}' could not be detached from "
                f"role '{role_name}': {detail}"
            )
            print(f"  ! user {user.name}: {detail}", file=sys.stderr)
    return warnings, snapshot


def users_assigned_to_roles(
    stack: stack_lib.Catalog, role_names: set[str]
) -> list[UserRoleBinding]:
    """Snapshot user assignments for the given roles without modifying state."""
    bindings: list[UserRoleBinding] = []
    for user in stack.admin.users.list():
        primary = user.role.name if user.role else None
        extras = [
            r.name for r in (getattr(user, "extra_roles", None) or []) if r is not None
        ]
        if primary in role_names or any(e in role_names for e in extras):
            bindings.append(
                UserRoleBinding(user_name=user.name, primary=primary, extras=extras)
            )
    return bindings


def restore_user_role_bindings(
    stack: stack_lib.Catalog, bindings: list[UserRoleBinding], *, verbose: bool = False
) -> list[str]:
    """Reapply captured user role assignments after affected roles exist again."""
    warnings: list[str] = []
    for binding in bindings:
        _print_apply_step(f"restore user {binding.user_name}", verbose=verbose)
        try:
            stack.admin.users.set_role(
                binding.user_name,
                binding.primary or "",
                extra_roles=binding.extras or None,
            )
            print(f"  ~ user {binding.user_name} (restored)")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(
                f"User '{binding.user_name}' role bindings could not be "
                f"restored: {detail}"
            )
            print(f"  ! user {binding.user_name}: {detail}", file=sys.stderr)
    return warnings


def clear_sso_config(stack: stack_lib.Catalog, *, verbose: bool = False) -> list[str]:
    """Clear the entire SSO config.

    users.set_role and users.remove_roles are rejected while any SSO config
    exists (SsoConfigConflict). Callers reset the config entirely, perform
    the user/role mutations, then let the reapply step rebuild SSO from the
    desired YAML.
    """
    warnings: list[str] = []
    _print_apply_step("clear sso config", verbose=verbose)
    try:
        stack.admin.sso_config.set(None)
        print("  ~ sso config (cleared)")
    except Exception as exc:
        detail = format_exception(exc)
        warnings.append(f"SSO config could not be cleared: {detail}")
        print(f"  ! sso config: {detail}", file=sys.stderr)
    return warnings


def reset_policy(
    stack: stack_lib.Catalog,
    title: str,
    current: CurrentState,
    *,
    verbose: bool = False,
    already_deleted_roles: set[str] | None = None,
) -> tuple[list[str], list[UserRoleBinding]]:
    """Delete a managed policy and any managed roles referencing it.

    Before the deletes, clear the full SSO config and detach user
    assignments for the affected roles — the registry rejects
    roleDeleteManaged while either references still exist, and rejects
    user role mutations while any SSO config is present. Returns
    (warnings, user_bindings_snapshot) so the caller can restore user
    assignments once the new roles exist.

    In the cumulative-role model a single managed role can reference
    multiple policies, so resetting several drifted policies in one pass
    can ask us to delete the same role twice. Pass ``already_deleted_roles``
    (a mutable set shared across calls) to skip roles that a prior call
    has already handled; this function mutates the set to record the
    roles it processes.
    """
    warnings: list[str] = []
    user_snapshot: list[UserRoleBinding] = []
    deleted = already_deleted_roles if already_deleted_roles is not None else set()
    roles_to_delete = [
        r for r in managed_roles_using_policy(title, current) if r not in deleted
    ]
    if roles_to_delete:
        users_to_detach = users_assigned_to_roles(stack, set(roles_to_delete))
        if users_to_detach:
            warnings.extend(clear_sso_config(stack, verbose=verbose))
        else:
            warnings.extend(
                detach_sso_mappings_for_roles(
                    stack, set(roles_to_delete), verbose=verbose
                )
            )
        for role_name in roles_to_delete:
            w, snap = detach_users_from_role(stack, role_name, verbose=verbose)
            warnings.extend(w)
            user_snapshot.extend(snap)
    for role_name in roles_to_delete:
        try:
            _print_apply_step(f"delete role {role_name}", verbose=verbose)
            stack.admin.roles.delete(role_name)
            print(f"  - role {role_name}")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"Role '{role_name}' could not be deleted: {detail}")
            print(f"  ! role {role_name}: {detail}", file=sys.stderr)
        finally:
            deleted.add(role_name)
    try:
        _print_apply_step(f"delete policy {title}", verbose=verbose)
        stack.admin.policies.delete(title)
        print(f"  - policy {title}")
    except Exception as exc:
        detail = format_exception(exc)
        if _is_internal_server_error(detail):
            suffix = f" [{_describe_policy_state(stack, title)}]"
        else:
            suffix = ""
        warnings.append(f"Policy '{title}' could not be deleted: {detail}{suffix}")
        print(f"  ! policy {title}: {detail}{suffix}", file=sys.stderr)
    return warnings, user_snapshot


def _build_desired_acl_state(config: AclConfig) -> _DesiredAclState:
    policy_updates: dict[str, PolicyUpdate] = {}
    synthesized_roles: list[_SynthesizedRole] = []
    role_updates: dict[str, RoleUpdate] = {}
    sso_mappings: list[_SsoMapping] = []
    default_role_name: str | None = None
    warnings: list[str] = []

    cumulative_policy_titles: list[str] = []
    cumulative_admin_votes: list[tuple[str, bool]] = []
    for policy in config.policies:
        policy_updates[policy.name] = PolicyUpdate(
            title=policy.name,
            permissions=_permissions_for_buckets(policy.read, policy.read_write),
        )
        cumulative_policy_titles.append(policy.name)
        if policy.is_admin is not None:
            cumulative_admin_votes.append((policy.name, policy.is_admin))
        synthesized_role_name = policy.role_name or _synthesized_role_name(
            cumulative_policy_titles
        )
        synthesized_admin = _resolve_policy_admin_vote(
            cumulative_admin_votes,
            synthesized_role_name,
            warnings,
        )
        synthesized_role = _SynthesizedRole(
            name=synthesized_role_name,
            sso=policy.sso,
            policy_titles=list(cumulative_policy_titles),
            source_policies=list(cumulative_policy_titles),
            is_admin=synthesized_admin,
        )
        synthesized_roles.append(synthesized_role)
        role_updates[synthesized_role.name] = RoleUpdate(
            name=synthesized_role.name,
            policy_titles=list(cumulative_policy_titles),
        )
        for claim, values in policy.sso.items():
            for value in values:
                sso_mappings.append(
                    _SsoMapping(
                        claim=claim,
                        value=value,
                        role_name=synthesized_role.name,
                        admin=synthesized_role.is_admin,
                    )
                )
        if policy.default_role:
            default_role_name = synthesized_role.name

    static_roles: list[_ResolvedStaticRole] = []
    for role in config.roles.values():
        policy_titles = list(role.policies)
        inline_policy_title: str | None = None
        if role.read or role.read_write:
            inline_policy_title = f"{role.name}{INLINE_POLICY_SUFFIX}"
            policy_updates[inline_policy_title] = PolicyUpdate(
                title=inline_policy_title,
                permissions=_permissions_for_buckets(role.read, role.read_write),
            )
            policy_titles.append(inline_policy_title)
        resolved_role = _ResolvedStaticRole(
            name=role.name,
            sso=role.sso,
            policy_titles=policy_titles,
            is_admin=role.is_admin,
            default_role=role.default_role,
            inline_policy_title=inline_policy_title,
        )
        static_roles.append(resolved_role)
        role_updates[role.name] = RoleUpdate(
            name=role.name, policy_titles=policy_titles
        )
        for claim, values in role.sso.items():
            for value in values:
                sso_mappings.append(
                    _SsoMapping(
                        claim=claim,
                        value=value,
                        role_name=role.name,
                        admin=True if role.is_admin else None,
                    )
                )
        if role.default_role:
            default_role_name = role.name

    return _DesiredAclState(
        policy_updates=policy_updates,
        synthesized_roles=synthesized_roles,
        static_roles=static_roles,
        role_updates=role_updates,
        sso_mappings=sso_mappings,
        default_role_name=default_role_name,
        warnings=warnings,
    )


def _resolve_policy_admin_vote(
    votes: list[tuple[str, bool]], role_name: str, warnings: list[str]
) -> bool | None:
    false_votes = [name for name, is_admin in votes if not is_admin]
    true_votes = [name for name, is_admin in votes if is_admin]
    if false_votes:
        if true_votes:
            warnings.append(
                "Policy config.is_admin: false vetoes true for generated role "
                f"'{role_name}' (true: {', '.join(true_votes)}; "
                f"false: {', '.join(false_votes)})"
            )
        return False
    if true_votes:
        return True
    return None


def _validate_top_level_keys(raw: dict[str, Any]) -> None:
    unknown_keys = sorted(set(raw) - ACL_TOP_LEVEL_KEYS)
    if unknown_keys:
        raise ValueError(
            "Unknown top-level ACL keys: "
            + ", ".join(unknown_keys)
            + ". Supported keys: "
            + ", ".join(sorted(ACL_TOP_LEVEL_KEYS))
            + "."
        )


def _validate_acl_entry_keys(value: dict[str, Any], *, section: str, name: str) -> None:
    allowed_keys = set(ACL_ENTRY_KEYS)
    if section == "policies":
        allowed_keys.add(POLICY_ROLE_NAME_KEY)
    if section == "roles":
        allowed_keys.add(CONFIG_POLICIES_KEY)
    unknown_keys = sorted(
        key for key in value if key not in allowed_keys and not key.startswith("sso.")
    )
    if not unknown_keys:
        return
    hint = (
        f" Supported ACL entry fields are {', '.join(sorted(ACL_ENTRY_KEYS))} "
        "and any `sso.<claim>` selector."
    )
    if section == "roles":
        hint += f" Explicit roles also support the magic {CONFIG_POLICIES_KEY} key."
    if section == "policies" and CONFIG_POLICIES_KEY in unknown_keys:
        hint += (
            f" {CONFIG_POLICIES_KEY} is only valid under top-level 'roles:' "
            "because it composes existing named policies."
        )
    raise ValueError(
        f"Unknown ACL fields in {section}.{name}: "
        + ", ".join(unknown_keys)
        + ". Supported fields: "
        + ", ".join([*sorted(allowed_keys), "sso.<claim>"])
        + "."
        + hint
    )


def _parse_acl_entry(value: dict[str, Any], field_name: str) -> _ParsedAclEntry:
    sso = _coerce_sso_selectors(value, field_name)
    read = _coerce_string_list(
        value.get("buckets.read", []), f"{field_name}.buckets.read"
    )
    read_write = _coerce_string_list(
        value.get("buckets.read_write", []), f"{field_name}.buckets.read_write"
    )
    default_role = value.get("config.default_role", False)
    if not isinstance(default_role, bool):
        raise ValueError(f"{field_name}.config.default_role must be a boolean")
    is_admin = value.get("config.is_admin")
    if is_admin is not None and not isinstance(is_admin, bool):
        raise ValueError(f"{field_name}.config.is_admin must be a boolean")
    return _ParsedAclEntry(
        sso=sso,
        read=_dedupe_preserve_order(read),
        read_write=_dedupe_preserve_order(read_write),
        default_role=default_role,
        is_admin=is_admin,
    )


def _validate_policy_ladder(policies: list[AclPolicy]) -> None:
    for previous, current in zip(policies, policies[1:]):
        if _policy_audience_is_compatible(current.sso, previous.sso):
            continue
        raise ValueError(
            "Policy ladder is not nested: "
            f"policy '{current.name}' has SSO selectors {_format_sso_selectors(current.sso)}, "
            f"which are not a subset of policy '{previous.name}' selectors "
            f"{_format_sso_selectors(previous.sso)}. "
            "Without a declared hierarchy, only explicitly repeated groups or a prior "
            f"'{EVERYONE_GROUP}' audience are accepted."
        )


def _policy_audience_is_compatible(
    current_sso: dict[str, list[str]], previous_sso: dict[str, list[str]]
) -> bool:
    if EVERYONE_GROUP in previous_sso.get("groups", []):
        return True
    for claim, current_values in current_sso.items():
        previous_values = previous_sso.get(claim)
        if previous_values is None:
            return False
        if not set(current_values) <= set(previous_values):
            return False
    return True


def _validate_synthetic_role_names(
    policies: list[AclPolicy], declared_role_names: set[str]
) -> None:
    cumulative_policy_titles: list[str] = []
    generated_role_sources: dict[str, list[str]] = {}
    for policy in policies:
        cumulative_policy_titles.append(policy.name)
        role_name = policy.role_name or _synthesized_role_name(cumulative_policy_titles)
        if role_name in declared_role_names:
            raise ValueError(
                f"Synthesized role '{role_name}' from policy ladder "
                f"{', '.join(cumulative_policy_titles)} conflicts with declared role "
                f"'{role_name}'"
            )
        previous_source = generated_role_sources.get(role_name)
        if previous_source is not None:
            raise ValueError(
                f"Synthesized role '{role_name}' from policy ladder "
                f"{', '.join(cumulative_policy_titles)} conflicts with the role "
                f"generated from {', '.join(previous_source)}"
            )
        generated_role_sources[role_name] = list(cumulative_policy_titles)


def _synthesized_role_name(policy_titles: list[str]) -> str:
    return "_".join(reversed(policy_titles))


def _print_permissions(permissions: list[Permission]) -> None:
    for perm in permissions:
        level = perm.level.name if hasattr(perm.level, "name") else str(perm.level)
        print(f"    {level}: {perm.bucket}")


def _print_apply_step(message: str, *, verbose: bool) -> None:
    print(f"-> {message}")


def _print_verbose_state(
    diff: AclDiff, desired: AclConfig, current: CurrentState | None
) -> None:
    desired_state = _build_desired_acl_state(desired)
    print("Desired ACL:")

    changed_buckets = set(diff.buckets_to_add)
    for bucket in sorted(all_buckets(desired)):
        prefix = "+" if bucket in changed_buckets else "="
        print(f"{prefix} bucket {bucket}")

    created_policies = {policy.title for policy in diff.policies_to_create}
    updated_policies = {policy.title for policy in diff.policies_to_update}
    for policy in desired.policies:
        prefix = _diff_prefix(policy.name, created_policies, updated_policies)
        print(f"{prefix} policy {policy.name}")
        print(f"    sso: {_format_sso_selectors(policy.sso)}")
        _print_permissions(_permissions_for_buckets(policy.read, policy.read_write))
        if policy.default_role:
            print("    default_role: true")

    for role in desired_state.static_roles:
        if role.inline_policy_title is None:
            continue
        prefix = _diff_prefix(
            role.inline_policy_title, created_policies, updated_policies
        )
        print(f"{prefix} policy {role.inline_policy_title} (generated inline policy)")
        resolved_role = desired.roles[role.name]
        _print_permissions(
            _permissions_for_buckets(resolved_role.read, resolved_role.read_write)
        )

    created_roles = {role.name for role in diff.roles_to_create}
    updated_roles = {role.name for role in diff.roles_to_update}
    for synth_role in desired_state.synthesized_roles:
        prefix = _diff_prefix(synth_role.name, created_roles, updated_roles)
        sources = ", ".join(synth_role.source_policies)
        print(f"{prefix} role {synth_role.name} (synthesized from policies {sources})")
        print(f"    sso: {_format_sso_selectors(synth_role.sso)}")
        print(f"    policies: {', '.join(synth_role.policy_titles)}")
        if desired_state.default_role_name == synth_role.name:
            print("    default_role: true")

    for role in desired_state.static_roles:
        prefix = _diff_prefix(role.name, created_roles, updated_roles)
        print(f"{prefix} role {role.name}")
        print(f"    sso: {_format_sso_selectors(role.sso)}")
        print(f"    policies: {', '.join(role.policy_titles) or '(none)'}")
        if desired_state.default_role_name == role.name:
            print("    default_role: true")
        if role.inline_policy_title is not None:
            print(f"    inline policy: {role.inline_policy_title}")
        if role.is_admin:
            print("    admin: true")

    desired_sso_text = build_sso_config(desired)
    if desired_sso_text is not None:
        prefix = (
            "+"
            if diff.sso_is_create and diff.sso_needs_update
            else "~" if diff.sso_needs_update else "="
        )
        print(f"{prefix} sso config")
        for line in desired_sso_text.rstrip().splitlines():
            print(f"    {line}")
    elif current is not None and current.sso_config_text:
        print("= no sso config requested")


def _diff_prefix(name: str, created: set[str], updated: set[str]) -> str:
    if name in created:
        return "+"
    if name in updated:
        return "~"
    return "="


def _print_sso_summary(sso_text: str) -> None:
    """Print a human-friendly summary of SSO mappings."""
    loaded = yaml.safe_load(sso_text) or {}
    default_role = loaded.get("default_role")
    if default_role:
        print(f"    default_role: {default_role}")
    for mapping in loaded.get("mappings") or []:
        match_parts = []
        props = mapping.get("schema", {}).get("properties", {})
        for key, schema in props.items():
            if "contains" in schema:
                match_parts.append(f"{key}={schema['contains'].get('const', '?')}")
            elif "const" in schema:
                match_parts.append(f"{key}={schema['const']}")
        match_str = ", ".join(match_parts) or "?"
        roles = mapping.get("roles", [])
        admin = " (admin)" if mapping.get("admin") else ""
        print(f"    {match_str} -> [{', '.join(roles)}]{admin}")


def _coerce_sso_selectors(
    value: dict[str, Any], section_name: str
) -> dict[str, list[str]]:
    sso: dict[str, list[str]] = {}
    for key, raw_values in value.items():
        if not key.startswith("sso."):
            continue
        claim = key.removeprefix("sso.")
        if not claim:
            raise ValueError(f"'{section_name}.{key}' must include a claim name")
        values = _coerce_non_empty_string_list(raw_values, f"{section_name}.{key}")
        sso[claim] = _dedupe_preserve_order(values)
    if not sso:
        raise ValueError(
            f"'{section_name}' must include at least one sso.<claim> selector"
        )
    return sso


def _format_sso_selectors(sso: dict[str, list[str]]) -> str:
    if not sso:
        return "(none)"
    return ", ".join(f"sso.{claim}={values}" for claim, values in sso.items())


def _sso_claim_schema(claim: str, value: str) -> dict[str, Any]:
    if claim == "groups":
        return {"type": "array", "contains": {"const": value}}
    return {
        "anyOf": [
            {"const": value},
            {"type": "array", "contains": {"const": value}},
        ]
    }


def _coerce_non_empty_string_list(value: Any, field_name: str) -> list[str]:
    result = _coerce_string_list(value, field_name)
    if not result:
        raise ValueError(f"'{field_name}' must not be empty")
    return result


def _coerce_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"'{field_name}' must be a list")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"'{field_name}' entries must all be strings")
    return list(value)


def _permissions_for_buckets(
    read: list[str], read_write: list[str]
) -> list[Permission]:
    """Build the wire-level Permission list for a (read, read_write) pair.

    Drops any READ entry whose bucket also appears in read_write — RW implies R,
    and the registry's `RolePolicyBucketPermission` uses a composite primary
    key on `(role_policy_id, bucket_name)`, so emitting two rows for the same
    bucket trips a primary-key violation and surfaces as an opaque 500 from
    `policyCreateManaged` / `policyUpdateManaged`.
    """
    rw = set(read_write)
    permissions = [Permission.read(bucket) for bucket in sorted(set(read) - rw)]
    permissions.extend(Permission.read_write(bucket) for bucket in sorted(rw))
    return permissions


def _policy_uses_buckets(permissions: list[Permission], buckets: set[str]) -> set[str]:
    """Return the subset of *buckets* referenced by *permissions*."""
    return {permission.bucket for permission in permissions} & buckets


def _canonical_permissions(permissions: list[Permission]) -> list[tuple[str, str]]:
    return sorted(
        (permission.bucket, str(permission.level)) for permission in permissions
    )


def _dropped_permissions(
    sent: list[Permission], returned: list[Permission]
) -> list[str]:
    returned_set = set(_canonical_permissions(returned))
    return [
        f"{level.split('.')[-1]}:{bucket}"
        for bucket, level in _canonical_permissions(sent)
        if (bucket, level) not in returned_set
    ]


def _format_permissions(permissions: list[Permission]) -> str:
    return (
        ",".join(
            f"{level.split('.')[-1]}:{bucket}"
            for bucket, level in _canonical_permissions(permissions)
        )
        or "(none)"
    )


def _is_internal_server_error(detail: str) -> bool:
    """True iff the formatted error text looks like a server-side 500.

    Used to gate the refetch-and-describe diagnostic so we do not pay an
    extra `policies.list()` round trip on expected validation, auth, or
    not-found errors — those carry their own actionable text already.
    """
    return "Internal Server Error" in detail


def _describe_policy_state(stack: stack_lib.Catalog, title: str) -> str:
    """Re-fetch policy by title after a failed mutation; return a short
    diagnostic string describing what (if anything) is on the server now.

    Useful when a mutation returns a generic 500 without context: the
    refetch tells us whether the policy actually exists, what permissions
    it has, and what its id/arn are — turning an opaque "Internal Server
    Error" into something we can act on the next attempt.
    """
    try:
        for p in stack.admin.policies.list():
            if getattr(p, "title", None) == title:
                arn = getattr(p, "arn", None)
                pid = getattr(p, "id", None)
                perms = _format_permissions(getattr(p, "permissions", []) or [])
                arn_part = f", arn={arn}" if arn else ""
                return f"server now: id={pid}{arn_part}, permissions=[{perms}]"
        return "server now: policy not present"
    except Exception as inner:
        return f"refetch failed: {format_exception(inner)}"


def _same_yaml(left: str | None, right: str | None) -> bool:
    return yaml.safe_load(left or "") == yaml.safe_load(right or "")


def _resolve_policy_ids(
    policy_titles: list[str], known_policies: dict[str, Any]
) -> list[str]:
    return [known_policies[title].id for title in policy_titles]


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
