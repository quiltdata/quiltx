"""Declarative ACL reconciliation for Quilt stacks."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from quiltx.config import auto_login
from quilt3.admin import buckets as admin_buckets
from quilt3.admin import policies as admin_policies
from quilt3.admin import roles as admin_roles
from quilt3.admin import sso_config as admin_sso_config
from quilt3.admin import users as admin_users
from quilt3.admin.types import Permission

INLINE_POLICY_SUFFIX = "__inline"
ACL_TOP_LEVEL_KEYS = {"policies", "roles", "store_last_login_context"}
EVERYONE_GROUP = "Everyone"


@dataclass(frozen=True)
class AclPolicy:
    name: str
    groups: list[str] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    default_role: bool = False


@dataclass(frozen=True)
class AclStaticRole:
    name: str
    groups: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    is_admin: bool = False


@dataclass(frozen=True)
class AclConfig:
    policies: list[AclPolicy]
    roles: dict[str, AclStaticRole]
    store_last_login_context: bool = False


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
    groups: list[str]
    policy_titles: list[str]
    source_policies: list[str]


@dataclass(frozen=True)
class _ResolvedStaticRole:
    name: str
    groups: list[str]
    policy_titles: list[str]
    is_admin: bool
    inline_policy_title: str | None


@dataclass(frozen=True)
class _SsoMapping:
    group: str
    role_name: str
    admin: bool = False


@dataclass(frozen=True)
class _DesiredAclState:
    policy_updates: dict[str, PolicyUpdate]
    synthesized_roles: list[_SynthesizedRole]
    static_roles: list[_ResolvedStaticRole]
    role_updates: dict[str, RoleUpdate]
    sso_mappings: list[_SsoMapping]
    default_role_name: str | None


def format_exception(exc: Exception) -> str:
    """Format an exception, surfacing GraphQL error details when present."""
    base = str(exc) or exc.__class__.__name__
    errors = getattr(exc, "errors", None)
    if not isinstance(errors, list) or not errors:
        return base
    details: list[str] = []
    for error in errors:
        message = getattr(error, "message", None)
        if not message:
            continue
        path = getattr(error, "path", None)
        details.append(f"{message} (path: {path})" if path else str(message))
    if not details:
        return base
    return f"{base}: {'; '.join(details)}"


def parse_acl_config(path: str | Path) -> AclConfig:
    """Load and validate ACL configuration from YAML."""
    raw = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError("ACL config must be a mapping at the top level")

    _validate_top_level_keys(raw)

    store_last_login_context = raw.get("store_last_login_context", False)
    if not isinstance(store_last_login_context, bool):
        raise ValueError("'store_last_login_context' must be a boolean")

    raw_policies = raw.get("policies") or {}
    raw_roles = raw.get("roles") or {}

    if not isinstance(raw_policies, dict):
        raise ValueError("'policies' must be a mapping")
    if not isinstance(raw_roles, dict):
        raise ValueError("'roles' must be a mapping")

    policies: list[AclPolicy] = []
    policy_names: set[str] = set()
    default_policy_names: list[str] = []
    for name, value in raw_policies.items():
        if not isinstance(name, str):
            raise ValueError("Policy names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Policy '{name}' must be a mapping")
        if name.endswith(INLINE_POLICY_SUFFIX):
            raise ValueError(
                "Policy names may not end with "
                f"'{INLINE_POLICY_SUFFIX}'; that suffix is reserved for generated "
                "inline-role policies"
            )
        groups = _coerce_non_empty_string_list(
            value.get("sso.groups"), f"policies.{name}.sso.groups"
        )
        read = _coerce_string_list(
            value.get("buckets.read", []), f"policies.{name}.buckets.read"
        )
        read_write = _coerce_string_list(
            value.get("buckets.read_write", []),
            f"policies.{name}.buckets.read_write",
        )
        default_role = value.get("config.default_role", False)
        if not isinstance(default_role, bool):
            raise ValueError(f"policies.{name}.config.default_role must be a boolean")
        policy = AclPolicy(
            name=name,
            groups=_dedupe_preserve_order(groups),
            read=_dedupe_preserve_order(read),
            read_write=_dedupe_preserve_order(read_write),
            default_role=default_role,
        )
        policies.append(policy)
        policy_names.add(name)
        if default_role:
            default_policy_names.append(name)

    if len(default_policy_names) > 1:
        raise ValueError(
            "Only one policy may set config.default_role: true; found "
            + ", ".join(default_policy_names)
        )

    roles: dict[str, AclStaticRole] = {}
    role_names: set[str] = set()
    for name, value in raw_roles.items():
        if not isinstance(name, str):
            raise ValueError("Role names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Role '{name}' must be a mapping")
        reserved_inline_policy = f"{name}{INLINE_POLICY_SUFFIX}"
        if reserved_inline_policy in raw_policies:
            raise ValueError(
                f"Role '{name}' conflicts with reserved generated inline policy "
                f"'{reserved_inline_policy}'"
            )
        groups = _coerce_non_empty_string_list(
            value.get("sso.groups"), f"roles.{name}.sso.groups"
        )
        policy_refs = _coerce_string_list(
            value.get("config.policies", []), f"roles.{name}.config.policies"
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
        read = _coerce_string_list(
            value.get("buckets.read", []), f"roles.{name}.buckets.read"
        )
        read_write = _coerce_string_list(
            value.get("buckets.read_write", []),
            f"roles.{name}.buckets.read_write",
        )
        is_admin = value.get("config.is_admin", False)
        if not isinstance(is_admin, bool):
            raise ValueError(f"roles.{name}.config.is_admin must be a boolean")
        roles[name] = AclStaticRole(
            name=name,
            groups=_dedupe_preserve_order(groups),
            policies=_dedupe_preserve_order(policy_refs),
            read=_dedupe_preserve_order(read),
            read_write=_dedupe_preserve_order(read_write),
            is_admin=is_admin,
        )
        role_names.add(name)

    _validate_policy_ladder(policies)
    _validate_synthetic_role_names(policies, role_names)

    return AclConfig(
        policies=policies,
        roles=roles,
        store_last_login_context=store_last_login_context,
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


@auto_login
def fetch_current_state() -> CurrentState:
    """Fetch current buckets, policies, roles, and SSO configuration."""
    bucket_items = {bucket.name: bucket for bucket in admin_buckets.list()}

    managed_policies: dict[str, Any] = {}
    unmanaged_policies: dict[str, Any] = {}
    for policy in admin_policies.list():
        if policy.managed:
            managed_policies[policy.title] = policy
        else:
            unmanaged_policies[policy.title] = policy

    managed_roles: dict[str, Any] = {}
    unmanaged_roles: dict[str, Any] = {}
    for role in admin_roles.list():
        typename = getattr(role, "typename__", "")
        if typename == "ManagedRole":
            managed_roles[role.name] = role
        else:
            unmanaged_roles[role.name] = role

    sso_config = admin_sso_config.get()
    default_role = admin_roles.get_default()
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
    )


def compute_diff(desired: AclConfig, current: CurrentState) -> AclDiff:
    """Compute the actions required to reconcile ACL state."""
    desired_state = _build_desired_acl_state(desired)
    diff = AclDiff()
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
        name for name in current.managed_roles if name not in desired_role_names
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
    payload["store_last_login_context"] = config.store_last_login_context
    if desired_state.default_role_name is not None:
        payload["default_role"] = desired_state.default_role_name

    for mapping in desired_state.sso_mappings:
        payload["mappings"].append(
            {
                "schema": {
                    "type": "object",
                    "properties": {
                        "groups": {
                            "type": "array",
                            "contains": {"const": mapping.group},
                        }
                    },
                    "required": ["groups"],
                },
                "roles": [mapping.role_name],
                "admin": mapping.admin,
            }
        )

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

    if current.sso_config_text:
        print("  sso config")
        _print_sso_summary(current.sso_config_text)
    else:
        print("  sso config: (none)")


def _register_bucket_with_retry(
    bucket: str, control_account_id: str, *, assume_yes: bool
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
    admin_buckets.add(name=bucket, title=bucket, sns_notification_arn=sns_topic_arn)


def apply_acl(
    diff: AclDiff,
    current: CurrentState,
    *,
    verbose: bool = False,
    assume_yes: bool = False,
) -> list[str]:
    """Apply ACL changes. Returns any runtime warnings."""
    from quiltx import bucket as bucket_lib
    from quiltx import stack as stack_lib
    from quiltx.config import get_catalog_config

    warnings = list(diff.warnings)
    failed_buckets: set[str] = set()

    control_account_id: str | None = None
    if diff.buckets_to_add:
        try:
            config = get_catalog_config()
            catalog_name = stack_lib.extract_catalog_name(config)
            payload = stack_lib.load_stack_payload(catalog_name)
            if payload and payload.get("account_id"):
                control_account_id = str(payload["account_id"])
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(f"Could not load control account for bucket add: {exc}")

    for bucket in diff.buckets_to_add:
        try:
            _print_apply_step(f"add bucket {bucket}", verbose=verbose)
            if control_account_id is None:
                admin_buckets.add(bucket, bucket)
            else:
                _register_bucket_with_retry(
                    bucket, control_account_id, assume_yes=assume_yes
                )
            print(f"  + bucket {bucket}")
        except Exception as exc:  # pragma: no cover - external API surface
            failed_buckets.add(bucket)
            warnings.append(f"Bucket '{bucket}' could not be added: {exc}")
            print(f"  ! bucket {bucket}: {exc}", file=sys.stderr)

    known_policies = dict(current.all_policies)
    for policy in diff.policies_to_create:
        _print_apply_step(f"create policy {policy.title}", verbose=verbose)
        affected = _policy_uses_buckets(policy.permissions, failed_buckets)
        try:
            created = admin_policies.create_managed(
                policy.title, permissions=policy.permissions
            )
        except Exception as exc:
            hint = (
                f" (references failed buckets: {', '.join(sorted(affected))})"
                if affected
                else ""
            )
            detail = format_exception(exc)
            warnings.append(
                f"Policy '{policy.title}' could not be created{hint}: {detail}"
            )
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)
            continue
        known_policies[policy.title] = created
        print(f"  + policy {policy.title}")
        dropped = _dropped_permissions(policy.permissions, created.permissions)
        if dropped:
            detail = (
                f"server accepted create but dropped permissions: "
                f"{', '.join(dropped)}"
            )
            warnings.append(f"Policy '{policy.title}' {detail}")
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)
    for policy in diff.policies_to_update:
        _print_apply_step(f"update policy {policy.title}", verbose=verbose)
        affected = _policy_uses_buckets(policy.permissions, failed_buckets)
        try:
            updated = admin_policies.update_managed(
                policy.title,
                title=policy.title,
                permissions=policy.permissions,
                roles=[],
            )
        except Exception as exc:
            hint = (
                f" (references failed buckets: {', '.join(sorted(affected))})"
                if affected
                else ""
            )
            detail = format_exception(exc)
            warnings.append(
                f"Policy '{policy.title}' could not be updated{hint}: {detail}"
            )
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)
            continue
        known_policies[policy.title] = updated
        print(f"  ~ policy {policy.title}")
        dropped = _dropped_permissions(policy.permissions, updated.permissions)
        if dropped:
            detail = (
                f"server accepted update but dropped permissions: "
                f"{', '.join(dropped)}"
            )
            warnings.append(f"Policy '{policy.title}' {detail}")
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)

    for role in diff.roles_to_create:
        _print_apply_step(f"create role {role.name}", verbose=verbose)
        try:
            policy_ids = _resolve_policy_ids(role.policy_titles, known_policies)
            admin_roles.create_managed(role.name, policies=policy_ids)
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
            warnings.append(f"Role '{role.name}' could not be created: {detail}")
            print(f"  ! role {role.name}: {detail}", file=sys.stderr)
            continue
        print(f"  + role {role.name}")

    for role in diff.roles_to_update:
        _print_apply_step(f"update role {role.name}", verbose=verbose)
        try:
            policy_ids = _resolve_policy_ids(role.policy_titles, known_policies)
            admin_roles.update_managed(role.name, name=role.name, policies=policy_ids)
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

    if diff.sso_needs_update and diff.sso_config_text is not None:
        _print_apply_step("update sso config", verbose=verbose)
        try:
            admin_sso_config.set(diff.sso_config_text)
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"SSO config could not be updated: {detail}")
            print(f"  ! sso config: {detail}", file=sys.stderr)
        else:
            prefix = "+" if diff.sso_is_create else "~"
            print(f"  {prefix} sso config")

    for role_name in diff.roles_to_delete:
        try:
            _print_apply_step(f"delete role {role_name}", verbose=verbose)
            admin_roles.delete(role_name)
            print(f"  - role {role_name}")
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(
                f"Role '{role_name}' could not be deleted: {format_exception(exc)}"
            )

    for policy_title in diff.policies_to_delete:
        try:
            _print_apply_step(f"delete policy {policy_title}", verbose=verbose)
            admin_policies.delete(policy_title)
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


def detach_sso_mappings_for_roles(
    role_names: set[str], *, verbose: bool = False
) -> list[str]:
    """Rewrite the live SSO config so it no longer references the given roles.

    The registry rejects roleDeleteManaged while a role is still bound in the
    SSO mapping, so callers that need to delete synthetic roles must clear
    the mapping first. The recreate-and-reapply flow restores the mappings
    when the new role IDs exist.
    """
    warnings: list[str] = []
    current_sso = admin_sso_config.get()
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
        admin_sso_config.set(new_text)
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
    role_name: str, *, verbose: bool = False
) -> tuple[list[str], list[UserRoleBinding]]:
    """Remove a role from every user that has it assigned.

    The registry rejects roleDeleteManaged while a user still has the role
    as their primary or extra role. Returns (warnings, snapshot) where
    snapshot lets callers restore the original assignments once the role
    has been recreated.
    """
    warnings: list[str] = []
    snapshot: list[UserRoleBinding] = []
    default_role = admin_roles.get_default()
    fallback_name = default_role.name if default_role is not None else None
    for user in admin_users.list():
        primary = user.role.name if user.role else None
        extras = [
            r.name for r in (getattr(user, "extra_roles", None) or []) if r is not None
        ]
        if primary != role_name and role_name not in extras:
            continue
        snapshot.append(
            UserRoleBinding(user_name=user.name, primary=primary, extras=extras)
        )
        _print_apply_step(
            f"detach user {user.name} from role {role_name}", verbose=verbose
        )
        try:
            admin_users.remove_roles(user.name, [role_name], fallback=fallback_name)
            print(f"  ~ user {user.name} (detached {role_name})")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(
                f"User '{user.name}' could not be detached from "
                f"role '{role_name}': {detail}"
            )
            print(f"  ! user {user.name}: {detail}", file=sys.stderr)
    return warnings, snapshot


def users_assigned_to_roles(role_names: set[str]) -> list[UserRoleBinding]:
    """Snapshot user assignments for the given roles without modifying state."""
    bindings: list[UserRoleBinding] = []
    for user in admin_users.list():
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
    bindings: list[UserRoleBinding], *, verbose: bool = False
) -> list[str]:
    """Reapply captured user role assignments after affected roles exist again."""
    warnings: list[str] = []
    for binding in bindings:
        _print_apply_step(f"restore user {binding.user_name}", verbose=verbose)
        try:
            admin_users.set_role(
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


def clear_sso_config(*, verbose: bool = False) -> list[str]:
    """Clear the entire SSO config.

    users.set_role and users.remove_roles are rejected while any SSO config
    exists (SsoConfigConflict). Callers reset the config entirely, perform
    the user/role mutations, then let the reapply step rebuild SSO from the
    desired YAML.
    """
    warnings: list[str] = []
    _print_apply_step("clear sso config", verbose=verbose)
    try:
        admin_sso_config.set(None)
        print("  ~ sso config (cleared)")
    except Exception as exc:
        detail = format_exception(exc)
        warnings.append(f"SSO config could not be cleared: {detail}")
        print(f"  ! sso config: {detail}", file=sys.stderr)
    return warnings


def reset_policy(
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
        users_to_detach = users_assigned_to_roles(set(roles_to_delete))
        if users_to_detach:
            warnings.extend(clear_sso_config(verbose=verbose))
        else:
            warnings.extend(
                detach_sso_mappings_for_roles(set(roles_to_delete), verbose=verbose)
            )
        for role_name in roles_to_delete:
            w, snap = detach_users_from_role(role_name, verbose=verbose)
            warnings.extend(w)
            user_snapshot.extend(snap)
    for role_name in roles_to_delete:
        try:
            _print_apply_step(f"delete role {role_name}", verbose=verbose)
            admin_roles.delete(role_name)
            print(f"  - role {role_name}")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"Role '{role_name}' could not be deleted: {detail}")
            print(f"  ! role {role_name}: {detail}", file=sys.stderr)
        finally:
            deleted.add(role_name)
    try:
        _print_apply_step(f"delete policy {title}", verbose=verbose)
        admin_policies.delete(title)
        print(f"  - policy {title}")
    except Exception as exc:
        detail = format_exception(exc)
        warnings.append(f"Policy '{title}' could not be deleted: {detail}")
        print(f"  ! policy {title}: {detail}", file=sys.stderr)
    return warnings, user_snapshot


def _build_desired_acl_state(config: AclConfig) -> _DesiredAclState:
    policy_updates: dict[str, PolicyUpdate] = {}
    synthesized_roles: list[_SynthesizedRole] = []
    role_updates: dict[str, RoleUpdate] = {}
    sso_mappings: list[_SsoMapping] = []
    default_role_name: str | None = None

    cumulative_policy_titles: list[str] = []
    for policy in config.policies:
        policy_updates[policy.name] = PolicyUpdate(
            title=policy.name,
            permissions=_permissions_for_buckets(policy.read, policy.read_write),
        )
        cumulative_policy_titles.append(policy.name)
        synthesized_role_name = _synthesized_role_name(cumulative_policy_titles)
        synthesized_role = _SynthesizedRole(
            name=synthesized_role_name,
            groups=policy.groups,
            policy_titles=list(cumulative_policy_titles),
            source_policies=list(cumulative_policy_titles),
        )
        synthesized_roles.append(synthesized_role)
        role_updates[synthesized_role.name] = RoleUpdate(
            name=synthesized_role.name,
            policy_titles=list(cumulative_policy_titles),
        )
        for group in policy.groups:
            sso_mappings.append(
                _SsoMapping(group=group, role_name=synthesized_role.name)
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
            groups=role.groups,
            policy_titles=policy_titles,
            is_admin=role.is_admin,
            inline_policy_title=inline_policy_title,
        )
        static_roles.append(resolved_role)
        role_updates[role.name] = RoleUpdate(
            name=role.name, policy_titles=policy_titles
        )
        for group in role.groups:
            sso_mappings.append(
                _SsoMapping(group=group, role_name=role.name, admin=role.is_admin)
            )

    return _DesiredAclState(
        policy_updates=policy_updates,
        synthesized_roles=synthesized_roles,
        static_roles=static_roles,
        role_updates=role_updates,
        sso_mappings=sso_mappings,
        default_role_name=default_role_name,
    )


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


def _validate_policy_ladder(policies: list[AclPolicy]) -> None:
    for previous, current in zip(policies, policies[1:]):
        if _groups_are_nested(current.groups, previous.groups):
            continue
        violating_groups = sorted(set(current.groups) - set(previous.groups))
        if not violating_groups:
            violating_groups = current.groups
        raise ValueError(
            "Policy ladder is not nested: "
            f"policy '{current.name}' has groups {current.groups}, which are not a "
            f"subset of policy '{previous.name}' groups {previous.groups}. "
            "Without a declared hierarchy, only explicitly repeated groups or a prior "
            f"'{EVERYONE_GROUP}' audience are accepted. Offending groups: "
            + ", ".join(violating_groups)
        )


def _groups_are_nested(current_groups: list[str], previous_groups: list[str]) -> bool:
    current_set = set(current_groups)
    previous_set = set(previous_groups)
    return current_set <= previous_set or EVERYONE_GROUP in previous_set


def _validate_synthetic_role_names(
    policies: list[AclPolicy], declared_role_names: set[str]
) -> None:
    cumulative_policy_titles: list[str] = []
    for policy in policies:
        cumulative_policy_titles.append(policy.name)
        role_name = _synthesized_role_name(cumulative_policy_titles)
        if role_name in declared_role_names:
            raise ValueError(
                f"Synthesized role '{role_name}' from policy ladder "
                f"{', '.join(cumulative_policy_titles)} conflicts with declared role "
                f"'{role_name}'"
            )


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
        print(f"    groups: {', '.join(policy.groups)}")
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
        print(
            f"{prefix} role {synth_role.name} " f"(synthesized from policies {sources})"
        )
        print(f"    groups: {', '.join(synth_role.groups)}")
        print(f"    policies: {', '.join(synth_role.policy_titles)}")
        if desired_state.default_role_name == synth_role.name:
            print("    default_role: true")

    for role in desired_state.static_roles:
        prefix = _diff_prefix(role.name, created_roles, updated_roles)
        print(f"{prefix} role {role.name}")
        print(f"    groups: {', '.join(role.groups)}")
        print(f"    policies: {', '.join(role.policy_titles) or '(none)'}")
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
    permissions = [Permission.read(bucket) for bucket in sorted(set(read))]
    permissions.extend(
        Permission.read_write(bucket) for bucket in sorted(set(read_write))
    )
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


def _same_yaml(left: str | None, right: str | None) -> bool:
    return yaml.safe_load(left or "") == yaml.safe_load(right or "")


def _resolve_policy_ids(
    policy_titles: list[str], known_policies: dict[str, Any]
) -> list[str]:
    return [known_policies[title].id for title in policy_titles]


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))
