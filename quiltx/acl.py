"""Declarative ACL reconciliation for Quilt stacks."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from quilt3.admin import exceptions as quilt3_admin_exceptions
from quilt3.admin.types import Permission
from quiltx import stack as stack_lib

INLINE_POLICY_SUFFIX = "__inline"
ACL_TOP_LEVEL_KEYS = {"policies", "roles", "users", "buckets"}
ACL_ENTRY_KEYS = {
    "buckets.read",
    "buckets.read_write",
    "config.default_role",
    "config.is_admin",
}
USER_ENTRY_KEYS = {"role", "extra_roles", "admin"}
CONFIG_NO_PREFLIGHT_KEY = "config.no_preflight"
BUCKET_ENTRY_KEYS = {CONFIG_NO_PREFLIGHT_KEY}
POLICY_ROLE_NAME_KEY = "name"
CONFIG_DEFAULT_POLICY_KEY = "config.default_policy"
CONFIG_POLICIES_KEY = "config.policies"
CONFIG_SYNTHESIZE_KEY = "config.synthesize"
CONFIG_UNMANAGED_KEY = "config.unmanaged"
EVERYONE_GROUP = "Everyone"
SSO_EMAIL_CLAIM = "email"
USERNAME_MAX_LENGTH = 64
"""How much of an address the registry keeps as a username.

SSO self-registration names an account ``email[:64]``, so deriving the same name
leaves a pre-created account indistinguishable from one that signed itself up.
"""
REGISTRY_MANAGED_POLICY_EXCLUSIONS = frozenset({"CanaryBucketAccess"})
REGISTRY_MANAGED_ROLE_EXCLUSIONS = frozenset({"Canary"})
BUILTIN_BUCKET_REGISTRATION_FIELDS = {
    "ReadQuiltBucket": "buckets.read",
    "ReadWriteQuiltBucket": "buckets.read_write",
}


@dataclass(frozen=True)
class AclPolicy:
    name: str
    sso: dict[str, list[str]] = field(default_factory=dict)
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    default_role: bool = False
    default_policy: bool = False
    """Compose this policy into every managed role: a floor, not a fallback.

    ``default_role`` fires only when an authenticated user's claims matched no
    mapping, so a *specific* grant costs a user the general one: whoever matches
    a narrow selector never reaches the default role and loses the open buckets
    unless every narrow role repeats the general policy. A default policy is
    granted through the roles a user already matched, which needs no extra role
    in their set and so cannot disturb the server's active-role selection.

    Requires ``synthesize`` to be false; see ``parse_acl_config_text``.
    """
    is_admin: bool | None = None
    role_name: str | None = None
    synthesize: bool = True


@dataclass(frozen=True)
class AclStaticRole:
    name: str
    sso: dict[str, list[str]] = field(default_factory=dict)
    policies: list[str] = field(default_factory=list)
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)
    default_role: bool = False
    is_admin: bool = False
    unmanaged: bool = False
    """Reference an existing unmanaged (catalog built-in) role by name only.

    Unmanaged roles are IAM-role-backed and their permissions live outside the
    registry, so quiltx never creates, updates, or deletes them. Declaring one
    keeps it addressable from ``users:``, SSO selectors, and
    ``config.default_role`` so a captured ACL stays replayable. The built-in
    QuiltStack bucket roles may also carry their matching ``buckets.*`` field
    as a registration reference; it never changes the role's IAM permissions.
    """


@dataclass(frozen=True)
class AclUserConfig:
    role: str
    extra_roles: tuple[str, ...] = ()
    admin: bool | None = None


@dataclass(frozen=True)
class AclBucketConfig:
    """Per-bucket registration options for a bucket the ACL declares."""

    no_preflight: bool = False
    """Register through GraphQL only, leaving the bucket's AWS setup alone.

    A bucket owned by another account is prepared once, owner-side, with
    ``quiltx bucket prepare``: the SNS topic exists and the catalog's control
    account already holds the grant. The identity applying the ACL is a catalog
    admin, not the bucket owner, so it cannot read or write that bucket's policy
    and must not be expected to — preflight fails and the bucket never
    registers. The CLI's ``--no-preflight`` says the same thing for every bucket
    in one run and is forgotten afterwards; declaring it here keeps the fact
    with the bucket, so a later plain apply (or a CI job) behaves the same way.
    """


@dataclass(frozen=True)
class AclConfig:
    policies: list[AclPolicy]
    roles: dict[str, AclStaticRole]
    users: dict[str, AclUserConfig] = field(default_factory=dict)
    buckets: dict[str, AclBucketConfig] = field(default_factory=dict)


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


@dataclass(frozen=True)
class AclUserUpdate:
    name: str
    role: str
    extra_roles: tuple[str, ...] = ()
    role_changed: bool = False
    admin: bool | None = None
    admin_changed: bool = False


@dataclass(frozen=True)
class UserAccess:
    """A user's effective access, as far as it can be determined."""

    primary_role: str | None
    extra_roles: tuple[str, ...] = ()
    admin: bool = False
    permissions: dict[str, str] = field(default_factory=dict)
    opaque_roles: tuple[str, ...] = ()
    """Roles whose bucket permissions cannot be enumerated from the registry."""

    @property
    def roles(self) -> tuple[str, ...]:
        primary = () if self.primary_role is None else (self.primary_role,)
        return (*primary, *self.extra_roles)


@dataclass(frozen=True)
class UserDowngrade:
    """One existing user whose effective access would shrink."""

    name: str
    before: UserAccess
    after: UserAccess
    lost_roles: tuple[str, ...] = ()
    admin_lost: bool = False
    lost_permissions: tuple[str, ...] = ()
    causes: tuple[str, ...] = ()
    undetermined: tuple[str, ...] = ()

    def is_downgrade(self) -> bool:
        """True when access is reduced or cannot be shown to be preserved.

        Losing a role name is not by itself a downgrade: renames and
        reassignments that keep the same effective permissions are neutral.
        """
        return bool(self.lost_permissions or self.admin_lost or self.undetermined)


@dataclass(frozen=True)
class BucketRegistrationFailure:
    """One bucket an apply attempted to register and could not."""

    name: str
    reason: str


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
    default_role_name: str | None = None
    default_role_needs_update: bool = False
    warnings: list[str] = field(default_factory=list)
    users_to_update: list[AclUserUpdate] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    user_downgrades: list[UserDowngrade] = field(default_factory=list)
    resolved_user_names: dict[str, str] = field(default_factory=dict)
    """``users:`` key -> server username, for the keys that resolved.

    A key may be an email, so reporting cannot assume it names an account.
    This is provenance for the diff, never a change on its own.
    """
    no_preflight_buckets: frozenset[str] = frozenset()
    """Buckets the config marks ``config.no_preflight: true``.

    ``apply_acl`` receives the diff but not the config, and registration mode is
    a property of the bucket rather than of the change, so the flag rides along
    here. It selects how a bucket in ``buckets_to_add`` is registered and is
    never a change on its own.
    """
    default_policy_titles: frozenset[str] = frozenset()
    """Policies the config marks ``config.default_policy: true``.

    Composed into every managed role, so one of these failing to create costs
    every role create and update rather than only the roles that named it.
    ``apply_acl`` gets the diff and not the config, so like
    ``no_preflight_buckets`` the fact rides along here; it tells a skipped role
    apart from the reason it was skipped and is never a change on its own.
    """

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
                self.users_to_update,
                self.sso_needs_update,
                self.default_role_needs_update,
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
    unmanaged: bool = False


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
    unmanaged_role_names: frozenset[str] = frozenset()

    def all_role_names(self) -> set[str]:
        """Every role the config addresses, managed or reference-only."""
        return set(self.role_updates) | set(self.unmanaged_role_names)


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
    """Load and validate ACL configuration from a YAML file."""
    return parse_acl_config_text(Path(path).read_text())


def parse_acl_config_text(text: str) -> AclConfig:
    """Load and validate ACL configuration from YAML text."""
    raw = yaml.safe_load(text) or {}
    if not isinstance(raw, dict):
        raise ValueError("ACL config must be a mapping at the top level")

    _validate_top_level_keys(raw)

    raw_policies = raw.get("policies") or {}
    raw_roles = raw.get("roles") or {}
    raw_users = raw.get("users", {})
    raw_bucket_configs = raw.get("buckets", {})

    if not isinstance(raw_policies, dict):
        raise ValueError("'policies' must be a mapping")
    if not isinstance(raw_roles, dict):
        raise ValueError("'roles' must be a mapping")
    if not isinstance(raw_users, dict):
        raise ValueError("'users' must be a mapping")
    if not isinstance(raw_bucket_configs, dict):
        raise ValueError("'buckets' must be a mapping")

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
        synthesize = value.get(CONFIG_SYNTHESIZE_KEY, True)
        if not isinstance(synthesize, bool):
            raise ValueError(
                f"policies.{name}.{CONFIG_SYNTHESIZE_KEY} must be a boolean"
            )
        default_policy = value.get(CONFIG_DEFAULT_POLICY_KEY, False)
        if not isinstance(default_policy, bool):
            raise ValueError(
                f"policies.{name}.{CONFIG_DEFAULT_POLICY_KEY} must be a boolean"
            )
        if default_policy and synthesize:
            # Checked before the entry parse so the reported problem is the
            # contradiction, not the missing selector it implies.
            raise ValueError(
                f"policies.{name}.{CONFIG_DEFAULT_POLICY_KEY} requires "
                f"{CONFIG_SYNTHESIZE_KEY}: false because a default policy is "
                "granted to every managed role: a ladder rung declares the "
                "audience its sso.<claim> selector names, and appending it to "
                "the rungs below would hand its buckets to those broader "
                "audiences while leaving their synthesized names unchanged"
            )
        entry = _parse_acl_entry(
            value,
            f"policies.{name}",
            require_sso_selector=synthesize,
        )
        if not synthesize:
            if POLICY_ROLE_NAME_KEY in value:
                raise ValueError(
                    f"policies.{name}.{POLICY_ROLE_NAME_KEY} is not valid when "
                    f"{CONFIG_SYNTHESIZE_KEY} is false because no role is synthesized"
                )
            if entry.sso:
                raise ValueError(
                    f"policies.{name} cannot include sso.<claim> selectors when "
                    f"{CONFIG_SYNTHESIZE_KEY} is false"
                )
            if entry.default_role:
                raise ValueError(
                    f"policies.{name}.config.default_role cannot be true when "
                    f"{CONFIG_SYNTHESIZE_KEY} is false"
                )
            if "config.is_admin" in value:
                raise ValueError(
                    f"policies.{name}.config.is_admin is not valid when "
                    f"{CONFIG_SYNTHESIZE_KEY} is false because no role is synthesized"
                )
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
            default_policy=default_policy,
            role_name=role_name,
            synthesize=synthesize,
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
        entry = _parse_acl_entry(value, f"roles.{name}", require_sso_selector=False)
        if not entry.sso and entry.is_admin:
            raise ValueError(
                f"roles.{name}.config.is_admin cannot be true without an "
                "sso.<claim> selector"
            )
        unmanaged = value.get(CONFIG_UNMANAGED_KEY, False)
        if not isinstance(unmanaged, bool):
            raise ValueError(f"roles.{name}.{CONFIG_UNMANAGED_KEY} must be a boolean")
        if unmanaged:
            allowed_registration_field = BUILTIN_BUCKET_REGISTRATION_FIELDS.get(name)
            forbidden = sorted(
                key
                for key in (CONFIG_POLICIES_KEY, "buckets.read", "buckets.read_write")
                if key in value
                and (key == CONFIG_POLICIES_KEY or key != allowed_registration_field)
            )
            if forbidden:
                raise ValueError(
                    f"roles.{name} cannot set {', '.join(forbidden)} when "
                    f"{CONFIG_UNMANAGED_KEY} is true: an unmanaged role's "
                    "permissions live outside the registry and are never modified"
                )
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
            unmanaged=unmanaged,
        )
        role_names.add(name)
        if entry.default_role:
            default_role_sources.append(f"roles.{name}")

    users: dict[str, AclUserConfig] = {}
    for name, value in raw_users.items():
        if not isinstance(name, str):
            raise ValueError("User names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"User '{name}' must be a mapping")
        unknown_fields = set(value) - USER_ENTRY_KEYS
        if unknown_fields:
            raise ValueError(
                f"Unknown fields in users.{name}: "
                + ", ".join(sorted(str(field) for field in unknown_fields))
            )
        if "role" not in value:
            raise ValueError(f"users.{name}.role is required")
        role = value["role"]
        if not isinstance(role, str) or not role.strip():
            raise ValueError(f"users.{name}.role must be a non-empty string")
        role = role.strip()
        extra_roles = _coerce_string_list(
            value.get("extra_roles", []), f"users.{name}.extra_roles"
        )
        extra_roles = _dedupe_preserve_order(extra_roles)
        if role in extra_roles:
            raise ValueError(
                f"users.{name}.extra_roles must not include primary role '{role}'"
            )
        admin: bool | None = None
        if "admin" in value:
            admin = value["admin"]
            if not isinstance(admin, bool):
                raise ValueError(f"users.{name}.admin must be a boolean")
        users[name] = AclUserConfig(
            role=role,
            extra_roles=tuple(extra_roles),
            admin=admin,
        )

    buckets: dict[str, AclBucketConfig] = {}
    for name, value in raw_bucket_configs.items():
        if not isinstance(name, str):
            raise ValueError("Bucket names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Bucket '{name}' must be a mapping")
        unknown_fields = set(value) - BUCKET_ENTRY_KEYS
        if unknown_fields:
            raise ValueError(
                f"Unknown fields in buckets.{name}: "
                + ", ".join(sorted(str(field) for field in unknown_fields))
                + ". Supported fields: "
                + ", ".join(sorted(BUCKET_ENTRY_KEYS))
                + "."
            )
        no_preflight = value.get(CONFIG_NO_PREFLIGHT_KEY, False)
        if not isinstance(no_preflight, bool):
            raise ValueError(
                f"buckets.{name}.{CONFIG_NO_PREFLIGHT_KEY} must be a boolean"
            )
        buckets[name] = AclBucketConfig(no_preflight=no_preflight)

    if len(default_role_sources) > 1:
        raise ValueError(
            "Only one ACL entry may set config.default_role: true; found "
            + ", ".join(default_role_sources)
        )

    _validate_policy_ladder(policies)
    _validate_synthetic_role_names(policies, role_names)

    has_sso_selectors = any(policy.sso for policy in policies) or any(
        role.sso for role in roles.values()
    )
    if has_sso_selectors and not default_role_sources:
        raise ValueError(
            "ACL configs with sso.<claim> selectors must set "
            "config.default_role: true on exactly one policy or role"
        )

    return AclConfig(
        policies=policies,
        roles=roles,
        users=users,
        buckets=buckets,
    )


def all_buckets(config: AclConfig) -> set[str]:
    """Return all buckets referenced by the ACL config.

    A ``buckets:`` key counts as a reference on its own. The block is
    declarative, so naming a bucket there is a statement that the catalog should
    hold it, and the annotation has to be usable on a bucket whose grants are
    added in a later commit.
    """
    result: set[str] = set(config.buckets)
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
    diff.no_preflight_buckets = frozenset(
        name for name, config in desired.buckets.items() if config.no_preflight
    )
    diff.default_policy_titles = frozenset(
        policy.name for policy in desired.policies if policy.default_policy
    )

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

    desired_role_names = desired_state.all_role_names()
    for name in sorted(desired_state.unmanaged_role_names):
        if name in current.unmanaged_roles:
            continue
        if name in current.managed_roles:
            diff.warnings.append(
                f"Role '{name}' is declared {CONFIG_UNMANAGED_KEY}: true but exists "
                "as a managed role; leaving it unchanged."
            )
        else:
            diff.warnings.append(
                f"Role '{name}' is declared {CONFIG_UNMANAGED_KEY}: true but does "
                "not exist on the server; unmanaged roles are never created."
            )

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

    if (
        desired_state.default_role_name is not None
        and desired_state.default_role_name != current.default_role_name
    ):
        diff.default_role_name = desired_state.default_role_name
        diff.default_role_needs_update = True

    current_users = {user.name: user for user in current.users}
    current_users_by_email = _index_users_by_email(current.users)
    available_user_roles = set(desired_state.role_updates) | set(
        current.unmanaged_roles
    )
    resolved_users: dict[str, AclUserConfig] = {}
    keys_by_server_name: dict[str, str] = {}
    for name, configured_user in desired.users.items():
        requested_roles = {configured_user.role, *configured_user.extra_roles}
        unknown_roles = sorted(requested_roles - available_user_roles)
        if unknown_roles:
            diff.warnings.append(
                f"Configured user '{name}' references unknown or unmanaged-for-deletion "
                f"roles: {', '.join(unknown_roles)}; skipping."
            )
            continue
        resolved = _resolve_configured_user(name, current_users, current_users_by_email)
        if resolved.collision is not None:
            diff.warnings.append(f"Configured user {resolved.collision}")
        current_user = resolved.user
        if current_user is None:
            diff.notices.append(
                f"Configured user '{name}' does not exist on the server; skipping."
            )
            continue
        server_name = str(current_user.name)
        first_key = keys_by_server_name.get(server_name)
        if first_key is not None:
            # Two entries about one person cannot both be applied: the updates
            # are walked in order with append=False, so the later one would
            # replace the earlier one without saying so. Same reason the
            # undecidable key is fatal — either reading grants roles the author
            # did not write for that account.
            raise ValueError(
                f"Configured users '{first_key}' and '{name}' both address the "
                f"server account '{server_name}'; one entry would silently "
                "replace the other. Keep a single entry per account."
            )
        keys_by_server_name[server_name] = name
        diff.resolved_user_names[name] = server_name
        resolved_users[server_name] = configured_user
        current_role = current_user.role.name if current_user.role else None
        current_extras = tuple(
            role.name for role in (current_user.extra_roles or []) if role is not None
        )
        role_changed = (
            current_role != configured_user.role
            or current_extras != configured_user.extra_roles
        )
        admin_changed = configured_user.admin is not None and (
            bool(current_user.is_admin) != configured_user.admin
        )
        if role_changed or admin_changed:
            diff.users_to_update.append(
                AclUserUpdate(
                    name=server_name,
                    role=configured_user.role,
                    extra_roles=configured_user.extra_roles,
                    role_changed=role_changed,
                    admin=configured_user.admin,
                    admin_changed=admin_changed,
                )
            )

    desired_sso_text = build_sso_config(desired)
    if desired_sso_text is not None and not _same_yaml(
        current.sso_config_text, desired_sso_text
    ):
        diff.sso_config_text = desired_sso_text
        diff.sso_is_create = current.sso_config_text is None
        diff.sso_needs_update = True

    diff.user_downgrades = analyze_user_downgrades(
        desired,
        current,
        diff,
        desired_state=desired_state,
        resolved_users=resolved_users,
    )

    return diff


def _index_users_by_email(users: list[Any]) -> dict[str, list[Any]]:
    """Group server users by lowercased email.

    Emails are grouped rather than mapped one-to-one so a key matching several
    accounts can be reported instead of silently resolving to whichever user
    the registry happened to list first.
    """
    index: dict[str, list[Any]] = {}
    for user in users:
        email = getattr(user, "email", None)
        if not email:
            continue
        index.setdefault(str(email).lower(), []).append(user)
    return index


@dataclass(frozen=True)
class _ResolvedUser:
    """The account a key addresses, and any collision resolving it stepped over."""

    user: Any | None = None
    collision: str | None = None
    """Set when the key also reached other accounts by email.

    A sentence about the key, phrased so a caller can prefix its own context
    ("Configured user ...", "Roster address ..."). Resolution succeeded; this is
    the risk it stepped over, never a reason to stop.
    """


def _resolve_configured_user(
    key: str,
    users_by_name: dict[str, Any],
    users_by_email: dict[str, list[Any]],
) -> _ResolvedUser:
    """Return the server user a ``users:`` key addresses, if any.

    ``user.name`` is email-shaped for SSO self-registrations and handle-shaped
    for admin-created accounts, and a captured ACL mixes both without marking
    which is which. Usernames therefore win, so a key that names an account
    always means that account, and email is only a fallback for authors working
    from a roster of addresses.

    Precedence has to hold even when a *different* account carries the key as
    its email, because ``--yaml`` keys every entry by ``user.name``: refusing
    that combination would reject the tool's own capture of any catalog holding
    an SSO self-registration whose name is another account's email, with an
    error asking for the username the capture already used. The collision is
    reported instead, so an author who meant the other person can rekey.

    Only a key that names no account and is the email of two or more is fatal:
    nothing there decides between them, and either reading regrants someone the
    author did not name.
    """
    named = users_by_name.get(key)
    by_email = users_by_email.get(key.lower(), [])
    if named is not None:
        others = [user for user in by_email if user is not named]
        if others:
            return _ResolvedUser(
                user=named,
                collision=(
                    f"'{key}' is the server username of one account and the "
                    f"email of {_quote_user_names(others)}; it resolves to the "
                    f"account named '{key}', because a key that names an account "
                    "always means that account. Rekey it to the other account's "
                    "username if that is who was meant."
                ),
            )
        return _ResolvedUser(user=named)
    if len(by_email) > 1:
        raise ValueError(
            f"Configured user '{key}' is ambiguous: it is the email of "
            f"{_quote_user_names(by_email)}; key this entry by the server "
            "username of the account you mean."
        )
    return _ResolvedUser(user=by_email[0] if by_email else None)


def _resolve_configured_users(
    desired: AclConfig, current: CurrentState
) -> dict[str, AclUserConfig]:
    """Map server username -> ``users:`` entry for every key that resolves.

    The standalone form of what ``compute_diff`` builds as it walks ``users:``.
    An undecidable key is skipped rather than raised on: this feeds analysis, and
    a caller who has not gone through ``compute_diff`` should still get findings
    for the keys that do resolve.
    """
    users_by_name = {
        str(user.name): user for user in current.users if getattr(user, "name", None)
    }
    users_by_email = _index_users_by_email(current.users)
    resolved: dict[str, AclUserConfig] = {}
    for key, configured_user in desired.users.items():
        try:
            match = _resolve_configured_user(key, users_by_name, users_by_email)
        except ValueError:
            continue
        if match.user is not None:
            resolved[str(match.user.name)] = configured_user
    return resolved


def _quote_user_names(users: list[Any]) -> str:
    return ", ".join(sorted(f"'{getattr(user, 'name', None)}'" for user in users))


@dataclass(frozen=True)
class UserCreation:
    """One account an ``sso.email`` roster names and the server does not hold."""

    name: str
    email: str
    role: str
    extra_roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class UserCreationPlan:
    """What creating the missing roster accounts would do, before it is done.

    Creation mails every new account, so the plan is computed and shown first
    and carried out second: the addresses are the only part of the operation a
    reviewer can still change their mind about.
    """

    creations: tuple[UserCreation, ...] = ()
    existing: tuple[str, ...] = ()
    """Roster addresses an account already holds. Nothing to do, but provenance
    for a run that creates fewer accounts than the file lists addresses."""
    warnings: tuple[str, ...] = ()
    """One message per address the run creates no account for and should not.

    Covers addresses that cannot be created and addresses whose server state is
    odd enough to report, so a plan is never silent about an address it read.
    """


def sso_email_roster(
    config: AclConfig, *, desired_state: _DesiredAclState | None = None
) -> dict[str, list[str]]:
    """Return each ``sso.email`` address mapped to the roles it is granted.

    ``sso.email`` is the only selector that names individuals: ``sso.hd`` and
    ``sso.groups`` are set-valued, so a domain or group has no roster to read.
    The resolved desired state is walked rather than the raw config so a rung of
    the synthesized policy ladder contributes its roster exactly like a static
    role does, under the role name that will actually exist.

    Roles come back in declaration order, deduped. Addresses are matched
    case-insensitively and reported under the spelling the file used first, so
    two spellings of one person are one entry rather than two accounts.
    """
    state = desired_state or _build_desired_acl_state(config)
    canonical: dict[str, str] = {}
    roster: dict[str, list[str]] = {}
    for mapping in state.sso_mappings:
        if mapping.claim != SSO_EMAIL_CLAIM:
            continue
        address = canonical.setdefault(mapping.value.lower(), mapping.value)
        roles = roster.setdefault(address, [])
        if mapping.role_name not in roles:
            roles.append(mapping.role_name)
    return roster


def plan_user_creations(
    config: AclConfig,
    current: CurrentState,
    *,
    desired_state: _DesiredAclState | None = None,
) -> UserCreationPlan:
    """Work out which roster addresses have no account yet.

    An address that any account already answers for is left alone, so a repeat
    run creates nobody. Existence is decided by the same resolution ``users:``
    keys get: email first, then username. Email has to come first here because
    the derived username is truncated to ``USERNAME_MAX_LENGTH``, so a long
    address is not its own account's name and only the email index can find it.

    When several roles name the same person the last declaration becomes the
    active role and the earlier ones become extra roles. The generated SSO
    config sets ``union_roles: true`` and the catalog activates the
    last-matching role at first login, so the account starts where its own first
    login would have left it instead of somewhere a re-login would move it.

    An address is only created when every role its roster entry names will exist:
    the registry rejects a creation naming a role it does not hold, and the mail
    is sent by the creation, so attempting one that cannot succeed is worse than
    skipping it. The available set is the one ``compute_diff`` uses for ``users:``
    entries — managed roles this file declares, plus unmanaged roles the server
    already holds — so a dry run does not report a missing role that the same run
    creates, while a ``config.unmanaged: true`` role that does not exist is
    refused, since quiltx never creates one. An *existing* unmanaged role is
    creatable into on purpose: its selector would grant it at first login anyway,
    so pre-creating the account changes nothing about who ends up holding it. The
    permissions it confers are IAM-backed and therefore reported as undetermined
    by the downgrade analysis.
    """
    state = desired_state or _build_desired_acl_state(config)
    roster = sso_email_roster(config, desired_state=state)
    available_roles = set(state.role_updates) | set(current.all_roles)
    users_by_name = {
        str(user.name): user for user in current.users if getattr(user, "name", None)
    }
    users_by_email = _index_users_by_email(current.users)

    creations: list[UserCreation] = []
    existing: list[str] = []
    warnings: list[str] = []
    for address, roles in roster.items():
        held, held_warning = _roster_address_is_held(
            address, users_by_name, users_by_email
        )
        if held_warning is not None:
            warnings.append(held_warning)
        if held:
            existing.append(address)
            continue
        unavailable = [role for role in roles if role not in available_roles]
        if unavailable:
            warnings.append(
                f"Roster address '{address}' names role(s) "
                f"{', '.join(unavailable)}, which the server does not hold and "
                "this file does not create; not created. Unmanaged roles are "
                "never created by quiltx, so create the role first or drop the "
                "address."
            )
            continue
        name = address[:USERNAME_MAX_LENGTH]
        collision = users_by_name.get(name)
        if collision is not None:
            # Only reachable through truncation: an untruncated address that is
            # some account's username resolves above. The registry would reject
            # the duplicate name, so refuse the one address and keep going.
            other_email = getattr(collision, "email", None) or "(unknown)"
            warnings.append(
                f"Roster address '{address}' derives username '{name}', which "
                f"already belongs to a different account (email {other_email}); "
                "not created. Create this account by hand, or shorten the "
                f"address to under {USERNAME_MAX_LENGTH} characters."
            )
            continue
        *extra_roles, active_role = roles
        creations.append(
            UserCreation(
                name=name,
                email=address,
                role=active_role,
                extra_roles=tuple(extra_roles),
            )
        )
    return UserCreationPlan(
        creations=tuple(creations),
        existing=tuple(existing),
        warnings=tuple(warnings),
    )


def _roster_address_is_held(
    address: str,
    users_by_name: dict[str, Any],
    users_by_email: dict[str, list[Any]],
) -> tuple[bool, str | None]:
    """Return (some account already answers for *address*, anything odd about it).

    An ambiguous address is held twice over, so it counts as held. A roster is
    keyed by email and cannot be rekeyed by username, so unlike a ``users:``
    entry there is nothing an author could rewrite; raising here would abort an
    apply over an address that needs no action. It is still reported rather than
    folded into the "already have one" count, because two accounts answering for
    one address is server data nobody asked for and the roles the roster grants
    land on whichever of them logs in.
    """
    try:
        resolved = _resolve_configured_user(address, users_by_name, users_by_email)
    except ValueError:
        accounts = _quote_user_names(users_by_email.get(address.lower(), []))
        return True, (
            f"Roster address '{address}' is the email of {accounts}, so it counts "
            "as already onboarded and no account was created for it. A roster is "
            "keyed by email and cannot be rekeyed by username; resolve the "
            "duplicate accounts on the server."
        )
    if resolved.user is None:
        return False, None
    if resolved.collision is None:
        return True, None
    return True, f"Roster address {resolved.collision}"


def print_user_creations(
    plan: UserCreationPlan, *, dry_run: bool = False, stream: Any = None
) -> None:
    """Name every address that would be created and mailed.

    The registry generates a password-reset link and mails it as part of
    creating an account, with no way to suppress the send, so the addresses are
    printed in full before the prompt rather than summarized as a count.
    """
    out = sys.stdout if stream is None else stream
    if not plan.creations:
        return
    verb = "would be" if dry_run else "will be"
    print(
        f"!! CREATE AND EMAIL: {len(plan.creations)} account(s) {verb} created "
        "and sent a welcome and password-reset email:",
        file=out,
    )
    for creation in plan.creations:
        roles = ", ".join((creation.role, *creation.extra_roles))
        print(f"  - {creation.email} -> user {creation.name}, roles {roles}", file=out)
    print(
        "The registry sends this mail as part of creation; it cannot be recalled.",
        file=out,
    )


def create_roster_users(
    stack: stack_lib.Catalog,
    creations: Sequence[UserCreation],
    *,
    verbose: bool = False,
) -> list[str]:
    """Create the planned accounts, returning one warning per failure.

    Each address stands alone: one rejected creation must not cost the rest of
    the roster their accounts, so failures are collected the way the other apply
    steps collect theirs instead of ending the run.
    """
    warnings: list[str] = []
    for creation in creations:
        _print_apply_step(f"create user {creation.name}", verbose=verbose)
        try:
            stack.admin.users.create(
                creation.name,
                creation.email,
                creation.role,
                extra_roles=list(creation.extra_roles) or None,
            )
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"User '{creation.email}' could not be created: {detail}")
            print(f"  ! user {creation.email}: {detail}", file=sys.stderr)
        else:
            print(f"  + user {creation.name} (role {creation.role}, emailed)")
    return warnings


_PERMISSION_RANK = {"READ": 1, "READ_WRITE": 2}


def analyze_user_downgrades(
    desired: AclConfig,
    current: CurrentState,
    diff: AclDiff,
    *,
    desired_state: _DesiredAclState | None = None,
    applied_user_names: set[str] | None = None,
    resolved_users: dict[str, AclUserConfig] | None = None,
) -> list[UserDowngrade]:
    """Return existing users whose effective access *diff* would reduce.

    Effective access is composed role -> policy -> bucket permission, so
    reductions caused indirectly by policy edits, role deletion, SSO mapping
    replacement, or a default-role change are detected alongside explicit
    ``users:`` entries. Roles whose permissions the registry cannot enumerate
    (unmanaged, IAM-backed) are treated as opaque: losing one is reported as
    undetermined rather than assumed harmless.

    Pass *resolved_users* keyed by server username to analyse ``users:`` entries
    whose key is an email: server users can only be matched by their own name,
    so an unresolved key would read as "no entry" and hide the reduction it
    causes. *applied_user_names* is the older form of the same argument and
    assumes keys are usernames, so it names only the entries whose keys the
    caller already matched against the server.

    With neither kwarg the keys are resolved here, by the same username-then-email
    rule ``compute_diff`` applies. Intersecting the keys with server usernames
    instead would drop every email-keyed entry, which is the reporting hole the
    resolution rule exists to close.
    """
    state = desired_state or _build_desired_acl_state(desired)
    if resolved_users is None:
        if applied_user_names is not None:
            resolved_users = {
                name: desired.users[name]
                for name in applied_user_names
                if name in desired.users
            }
        else:
            resolved_users = _resolve_configured_users(desired, current)
    downgrades: list[UserDowngrade] = []
    for user in sorted(current.users, key=lambda item: str(getattr(item, "name", ""))):
        downgrade = _analyze_user_downgrade(user, current, diff, state, resolved_users)
        if downgrade is not None and downgrade.is_downgrade():
            downgrades.append(downgrade)
    return downgrades


def format_user_downgrade(downgrade: UserDowngrade) -> list[str]:
    """Render a multi-line before/after summary for one downgraded user."""
    before, after = downgrade.before, downgrade.after
    lines = [
        f"user {downgrade.name} would lose access",
        f"    primary role: {before.primary_role or '(none)'} "
        f"-> {after.primary_role or '(none)'}",
    ]
    if before.extra_roles or after.extra_roles:
        lines.append(
            f"    extra roles: {', '.join(before.extra_roles) or '(none)'} "
            f"-> {', '.join(after.extra_roles) or '(none)'}"
        )
    if downgrade.admin_lost:
        lines.append(
            f"    admin: {str(before.admin).lower()} -> {str(after.admin).lower()}"
        )
    if downgrade.lost_permissions:
        lines.append(f"    lost permissions: {', '.join(downgrade.lost_permissions)}")
    lines.extend(f"    cause: {cause}" for cause in downgrade.causes)
    lines.extend(f"    undetermined: {item}" for item in downgrade.undetermined)
    return lines


def summarize_user_downgrade(downgrade: UserDowngrade) -> str:
    """Render a one-line summary for stderr and generated YAML comments."""
    parts: list[str] = []
    if downgrade.lost_permissions:
        parts.append("loses " + ", ".join(downgrade.lost_permissions))
    if downgrade.admin_lost:
        parts.append("loses admin")
    if downgrade.lost_roles:
        parts.append("loses role(s) " + ", ".join(downgrade.lost_roles))
    parts.extend(downgrade.undetermined)
    detail = "; ".join(parts) or "effective access could not be shown to be preserved"
    return f"user {downgrade.name!r}: {detail}"


def print_user_downgrades(
    downgrades: list[UserDowngrade], *, stream: Any = None
) -> None:
    """Print a prominent, user-specific downgrade block for each entry."""
    out = sys.stdout if stream is None else stream
    for downgrade in downgrades:
        head, *rest = format_user_downgrade(downgrade)
        print(f"!! DOWNGRADE: {head}", file=out)
        for line in rest:
            print(line, file=out)


def print_bucket_registration_failures(
    failures: list[BucketRegistrationFailure], *, stream: Any = None
) -> None:
    """Print a prominent block naming every bucket that was not registered.

    An unregistered bucket is not a partial success that can be read off the
    warning count: no policy can grant access to a bucket the catalog does not
    hold, so each dependent policy fails too and the reason scrolls past between
    those errors, drift resets, and a reapply. Naming the buckets and their
    reasons in one block keeps the first cause visible.
    """
    out = sys.stdout if stream is None else stream
    if not failures:
        return
    print(
        f"!! BUCKET REGISTRATION FAILED: {len(failures)} bucket(s) not registered:",
        file=out,
    )
    for failure in failures:
        print(f"  - {failure.name}: {failure.reason}", file=out)
    print("Permissions referencing these buckets were not applied.", file=out)
    print(
        "If a bucket is owned by another account and already prepared with "
        "`quiltx bucket prepare`, declare it under `buckets:` with "
        f"`{CONFIG_NO_PREFLIGHT_KEY}: true`.",
        file=out,
    )


def default_policy_failure_message(title: str, skipped_roles: list[str]) -> str:
    """One sentence naming a default policy as the cause of skipped roles."""
    return (
        f"Policy '{title}' is declared {CONFIG_DEFAULT_POLICY_KEY}: true, so every "
        f"managed role composes it; it does not exist, so {len(skipped_roles)} "
        f"role(s) were skipped: {', '.join(skipped_roles)}."
    )


def print_default_policy_failures(
    skipped_by_policy: dict[str, list[str]], *, stream: Any = None
) -> None:
    """Print a prominent block naming a default policy that blocked every role.

    A default policy is a dependency of every managed role, so one that could not
    be created turns into an ``unknown policy`` line per role — including roles
    that never named it. Repeated per role that reads as many independent
    failures; named once here it reads as the single cause it is. The roles are
    left alone rather than created without the floor, because a role missing its
    default policy is a silently narrower grant than the file asks for.
    """
    out = sys.stdout if stream is None else stream
    if not skipped_by_policy:
        return
    print(
        f"!! DEFAULT POLICY MISSING: {len(skipped_by_policy)} default polic"
        f"{'y' if len(skipped_by_policy) == 1 else 'ies'} blocked every managed "
        "role in this apply:",
        file=out,
    )
    for title, roles in skipped_by_policy.items():
        print(f"  - {default_policy_failure_message(title, roles)}", file=out)
    print(
        "This is the root cause of the per-role 'unknown policy' errors above. "
        "The roles were left unchanged rather than created without the floor, "
        "which would have granted less than the file asks for. Fix the policy "
        "failure reported earlier and re-run.",
        file=out,
    )


def export_downgrade_warnings(current: CurrentState, yaml_text: str) -> list[str]:
    """Warn when replaying generated ACL YAML would not preserve access.

    The generated document is re-parsed and diffed against the state it was
    captured from, so any assignment or mapping the export could not represent
    surfaces as a concrete, per-user warning.
    """
    try:
        replayed = parse_acl_config_text(yaml_text)
        diff = compute_diff(replayed, current)
    except Exception as exc:
        return [
            "the generated ACL is not valid input for `quiltx catalog acl` "
            f"({format_exception(exc)}); replaying it may change effective access"
        ]
    return [summarize_user_downgrade(item) for item in diff.user_downgrades]


def _analyze_user_downgrade(
    user: Any,
    current: CurrentState,
    diff: AclDiff,
    state: _DesiredAclState,
    resolved_users: dict[str, AclUserConfig],
) -> UserDowngrade | None:
    name = getattr(user, "name", None)
    if not name:
        return None
    before = _current_user_access(user, current)
    if not before.roles and not before.admin:
        return None

    after, causes, undetermined = _projected_user_access(
        user, before, current, diff, state, resolved_users
    )
    after_roles = set(after.roles)
    lost_roles = tuple(role for role in before.roles if role not in after_roles)
    lost_permissions = tuple(
        f"{level}:{bucket}"
        for bucket, level in sorted(before.permissions.items())
        if _PERMISSION_RANK.get(after.permissions.get(bucket, ""), 0)
        < _PERMISSION_RANK.get(level, 0)
    )
    admin_lost = before.admin and not after.admin

    notes = list(undetermined)
    for role in before.opaque_roles:
        if role not in after_roles:
            notes.append(
                f"role {role!r} is unmanaged, so the access it granted cannot "
                "be enumerated or compared"
            )
    if lost_permissions or admin_lost or notes:
        for role in after.opaque_roles:
            if role not in set(before.roles):
                notes.append(
                    f"replacement role {role!r} is unmanaged, so whether it "
                    "restores that access cannot be determined"
                )

    return UserDowngrade(
        name=name,
        before=before,
        after=after,
        lost_roles=lost_roles,
        admin_lost=admin_lost,
        lost_permissions=lost_permissions,
        causes=tuple(dict.fromkeys(causes)),
        undetermined=tuple(dict.fromkeys(notes)),
    )


def _current_user_access(user: Any, current: CurrentState) -> UserAccess:
    primary = getattr(getattr(user, "role", None), "name", None)
    extras = tuple(
        role.name
        for role in (getattr(user, "extra_roles", None) or [])
        if role is not None and role.name != primary
    )
    permissions: dict[str, str] = {}
    opaque: list[str] = []
    for role_name in ((primary,) if primary else ()) + extras:
        role_permissions, known = _current_role_permissions(role_name, current)
        _merge_permissions(permissions, role_permissions)
        if not known:
            opaque.append(role_name)
    return UserAccess(
        primary_role=primary,
        extra_roles=extras,
        admin=bool(getattr(user, "is_admin", False)),
        permissions=permissions,
        opaque_roles=tuple(dict.fromkeys(opaque)),
    )


def _projected_user_access(
    user: Any,
    before: UserAccess,
    current: CurrentState,
    diff: AclDiff,
    state: _DesiredAclState,
    resolved_users: dict[str, AclUserConfig],
) -> tuple[UserAccess, list[str], list[str]]:
    name = user.name
    causes: list[str] = []
    undetermined: list[str] = []
    configured = resolved_users.get(name)

    if configured is not None:
        roles = [configured.role, *configured.extra_roles]
        causes.append("the users: entry reassigns roles")
    else:
        deleted = set(diff.roles_to_delete)
        roles = [role for role in before.roles if role not in deleted]
        causes.extend(
            f"role {role!r} would be deleted"
            for role in before.roles
            if role in deleted
        )
        # SSO-only users are re-mapped on every login, so a replacement SSO
        # document decides what they hold next. Only worth analysing when the
        # document actually changes.
        if (
            getattr(user, "is_sso_only", False)
            and state.sso_mappings
            and diff.sso_needs_update
        ):
            desired_selectors = _selectors_by_role(state.sso_mappings)
            dropped = [role for role in roles if role not in desired_selectors]
            causes.extend(
                f"no SSO mapping grants role {role!r}; an SSO-only user loses it "
                "at next login"
                for role in dropped
            )
            roles = [role for role in roles if role in desired_selectors]
            # A role can survive with different selectors. The registry does not
            # expose a user's IdP claims, so whether this user still matches the
            # new selectors is unknowable here.
            current_selectors = _current_selectors_by_role(current.sso_config_text)
            undetermined.extend(
                f"SSO selectors for role {role!r} change from "
                f"{_format_selectors(current_selectors.get(role, set()))} to "
                f"{_format_selectors(desired_selectors[role])}; whether this user "
                "still matches them cannot be determined from the registry"
                for role in roles
                if current_selectors.get(role, set()) != desired_selectors[role]
            )
        if not roles:
            fallback = state.default_role_name or current.default_role_name
            if fallback is None:
                causes.append("no role would remain and no default role is configured")
            else:
                causes.append(f"falls back to the default role {fallback!r}")
                roles = [fallback]

    primary = roles[0] if roles else None
    extras = tuple(dict.fromkeys(role for role in roles[1:] if role != primary))

    admin = before.admin
    if configured is not None and configured.admin is not None:
        admin = configured.admin
        if before.admin and not admin:
            causes.append("the users: entry sets admin: false")
    else:
        vetoed = sorted(
            {
                mapping.role_name
                for mapping in state.sso_mappings
                if mapping.admin is False
            }
            & {role for role in roles}
        )
        if before.admin and vetoed:
            admin = False
            causes.append(
                "SSO mapping for role(s) " + ", ".join(vetoed) + " vetoes admin"
            )

    permissions: dict[str, str] = {}
    opaque: list[str] = []
    for role_name in ((primary,) if primary else ()) + extras:
        role_permissions, known = _desired_role_permissions(role_name, state, current)
        _merge_permissions(permissions, role_permissions)
        if not known:
            opaque.append(role_name)

    after = UserAccess(
        primary_role=primary,
        extra_roles=extras,
        admin=admin,
        permissions=permissions,
        opaque_roles=tuple(dict.fromkeys(opaque)),
    )
    return after, causes, undetermined


def _current_role_permissions(
    name: str, current: CurrentState
) -> tuple[dict[str, str], bool]:
    """Return (bucket -> level, permissions_are_knowable) for a server role."""
    role = current.all_roles.get(name)
    if role is None:
        return {}, False
    permissions = _permission_map(getattr(role, "permissions", None))
    if name in current.unmanaged_roles:
        # IAM-backed: the registry does not expose the bucket grants.
        return permissions, False
    known = True
    for summary in getattr(role, "policies", None) or []:
        policy = current.all_policies.get(summary.title)
        if policy is None:
            known = False
            continue
        _merge_permissions(
            permissions, _permission_map(getattr(policy, "permissions", None))
        )
    return permissions, known


def _desired_role_permissions(
    name: str, state: _DesiredAclState, current: CurrentState
) -> tuple[dict[str, str], bool]:
    update = state.role_updates.get(name)
    if update is None:
        # Not managed by this config: an unmanaged reference, or a server role
        # the config leaves alone.
        server_permissions, server_known = _current_role_permissions(name, current)
        if name in state.unmanaged_role_names:
            return server_permissions, False
        return server_permissions, server_known
    permissions: dict[str, str] = {}
    known = True
    for title in update.policy_titles:
        policy_update = state.policy_updates.get(title)
        if policy_update is None:
            known = False
            continue
        _merge_permissions(permissions, _permission_map(policy_update.permissions))
    return permissions, known


def _selectors_by_role(
    mappings: list[_SsoMapping],
) -> dict[str, set[tuple[str, str]]]:
    selectors: dict[str, set[tuple[str, str]]] = {}
    for mapping in mappings:
        selectors.setdefault(mapping.role_name, set()).add(
            (mapping.claim, mapping.value)
        )
    return selectors


def _current_selectors_by_role(
    sso_config_text: str | None,
) -> dict[str, set[tuple[str, str]]]:
    """Decode the server SSO document into role -> {(claim, value)}.

    Mappings quiltx cannot decode are skipped, which makes a role look less
    granted than it is; the comparison that uses this therefore errs toward
    reporting the outcome as undetermined.
    """
    if not sso_config_text:
        return {}
    try:
        raw = yaml.safe_load(sso_config_text) or {}
    except yaml.YAMLError:
        return {}
    if not isinstance(raw, dict):
        return {}
    selectors: dict[str, set[tuple[str, str]]] = {}
    for mapping in raw.get("mappings") or []:
        decoded = _decode_acl_sso_mapping(mapping)
        if decoded is None:
            continue
        role_name, claim, value, _admin = decoded
        selectors.setdefault(role_name, set()).add((claim, value))
    return selectors


def _format_selectors(selectors: set[tuple[str, str]]) -> str:
    if not selectors:
        return "(none)"
    return ", ".join(f"sso.{claim}={value}" for claim, value in sorted(selectors))


def _permission_map(permissions: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for permission in permissions or []:
        level = str(getattr(permission, "level", "")).split(".")[-1]
        if level not in _PERMISSION_RANK:
            continue
        bucket = getattr(permission, "bucket", None)
        if not bucket:
            continue
        existing = result.get(bucket)
        if existing is None or _PERMISSION_RANK[existing] < _PERMISSION_RANK[level]:
            result[bucket] = level
    return result


def _merge_permissions(target: dict[str, str], source: dict[str, str]) -> None:
    for bucket, level in source.items():
        existing = target.get(bucket)
        if existing is None or _PERMISSION_RANK[existing] < _PERMISSION_RANK[level]:
            target[bucket] = level


def build_sso_config(config: AclConfig) -> str | None:
    """Translate the flat ACL config into Quilt's schema-based SSO YAML."""
    desired_state = _build_desired_acl_state(config)
    if not desired_state.sso_mappings:
        return None
    if desired_state.default_role_name is None:
        raise ValueError(
            "ACL configs with sso.<claim> selectors must set "
            "config.default_role: true on exactly one policy or role"
        )

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
        print_user_downgrades(diff.user_downgrades)
        for notice in diff.notices:
            print(f"NONFATAL: {notice}")
        for warning in diff.warnings:
            print(f"! {warning}")
        if not diff.has_changes() and not diff.warnings and not diff.notices:
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

    if diff.default_role_needs_update and diff.default_role_name is not None:
        print(f"~ default role {diff.default_role_name}")

    for user in diff.users_to_update:
        changes: list[str] = []
        if user.role_changed:
            changes.append("roles")
        if user.admin_changed:
            changes.append("admin")
        print(f"~ user {user.name} ({', '.join(changes)})")

    if diff.sso_needs_update:
        prefix = "+" if diff.sso_is_create else "~"
        print(f"{prefix} sso config")
        if verbose and diff.sso_config_text:
            for line in diff.sso_config_text.rstrip().splitlines():
                print(f"    {line}")

    print_user_downgrades(diff.user_downgrades)

    for notice in diff.notices:
        print(f"NONFATAL: {notice}")
    for warning in diff.warnings:
        print(f"! {warning}")

    if not diff.has_changes() and not diff.warnings and not diff.notices:
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


def current_state_as_acl_yaml(
    current: CurrentState,
    *,
    catalog: str,
    captured_on: str,
    omit_default_users: bool = False,
) -> str:
    """Return current state as replayable ACL YAML with capture metadata."""
    exported, _warnings = current_state_as_acl_yaml_with_warnings(
        current,
        catalog=catalog,
        captured_on=captured_on,
        omit_default_users=omit_default_users,
    )
    return exported


def current_state_as_acl_yaml_with_warnings(
    current: CurrentState,
    *,
    catalog: str,
    captured_on: str,
    omit_default_users: bool = False,
) -> tuple[str, list[str]]:
    """Return replayable ACL YAML and its already-computed downgrade risks.

    Managed policies are emitted as reusable policies and managed roles as static
    roles. This avoids inventing ladder semantics while preserving the server's
    existing policy-to-role composition. Generated ``__inline`` policies are
    folded back into their owning role.

    ``config.default_policy`` is authoring shorthand the server never stores, so
    a capture cannot and need not re-emit it: every role that received the floor
    already lists it in its composed ``config.policies``, which replays to the
    same state. Re-adding the flag by hand keeps the file shorter and re-arms it
    for roles added later.

    The ``buckets:`` block is not captured either, and that omission does bite:
    the registry records no per-bucket registration mode, so a capture cannot
    tell a bucket prepared owner-side in another account from one this identity
    owns. Replaying a capture against a catalog that has yet to register such a
    bucket runs preflight against it and fails. Re-add
    ``config.no_preflight: true`` for those buckets by hand, or replay with the
    global ``--no-preflight``. Replays against the catalog the capture came from
    are unaffected: its buckets are registered already, so nothing is added.

    Use this form when the caller must also report downgrade risks (for example,
    the CLI writes them to stderr). It computes the parse+diff analysis once and
    returns the same warnings embedded in the YAML's ``# not captured:`` notes.
    """
    notes: list[str] = []
    role_entries: dict[str, dict[str, Any]] = {}
    policy_entries: dict[str, dict[str, Any]] = {}
    represented_buckets: set[str] = set()

    managed_roles = {
        name: role
        for name, role in sorted(current.managed_roles.items())
        if name not in REGISTRY_MANAGED_ROLE_EXCLUSIONS
    }
    inline_policy_names = {f"{name}{INLINE_POLICY_SUFFIX}" for name in managed_roles}

    referenced_policy_names: set[str] = set()
    for name, role in managed_roles.items():
        entry: dict[str, Any] = {}
        policy_names = [
            policy.title for policy in (getattr(role, "policies", None) or [])
        ]
        own_inline = f"{name}{INLINE_POLICY_SUFFIX}"
        if own_inline in policy_names:
            inline_policy = current.all_policies.get(own_inline)
            if inline_policy is None:
                notes.append(f"missing generated inline policy {own_inline!r}")
            else:
                read, read_write, permission_notes = _acl_bucket_fields(inline_policy)
                notes.extend(permission_notes)
                represented_buckets.update(read)
                represented_buckets.update(read_write)
                if read:
                    entry["buckets.read"] = read
                if read_write:
                    entry["buckets.read_write"] = read_write
            policy_names = [title for title in policy_names if title != own_inline]
        unsupported_inline = sorted(
            title for title in policy_names if title in inline_policy_names
        )
        if unsupported_inline:
            notes.append(
                f"role {name!r} also references generated inline policies: "
                + ", ".join(unsupported_inline)
            )
            policy_names = [
                title for title in policy_names if title not in unsupported_inline
            ]
        if policy_names:
            entry[CONFIG_POLICIES_KEY] = policy_names
            referenced_policy_names.update(policy_names)
        role_entries[name] = entry

    policy_names_to_emit = {
        title
        for title in current.managed_policies
        if title not in REGISTRY_MANAGED_POLICY_EXCLUSIONS
        and title not in inline_policy_names
    }
    policy_names_to_emit.update(referenced_policy_names)
    for title in sorted(policy_names_to_emit):
        policy = current.all_policies.get(title)
        if policy is None:
            notes.append(f"role references unavailable policy {title!r}")
            continue
        read, read_write, permission_notes = _acl_bucket_fields(policy)
        notes.extend(permission_notes)
        represented_buckets.update(read)
        represented_buckets.update(read_write)
        policy_entry: dict[str, Any] = {CONFIG_SYNTHESIZE_KEY: False}
        if read:
            policy_entry["buckets.read"] = read
        if read_write:
            policy_entry["buckets.read_write"] = read_write
        policy_entries[title] = policy_entry

    # Existing unmanaged roles (the catalog's built-in defaults) are emitted as
    # reference-only entries so users, SSO selectors, and the default role that
    # point at them survive a capture/replay round trip. They are always
    # emitted, even when nothing currently references them. The matching bucket
    # fields on QuiltStack's two built-ins preserve registration only; their IAM
    # permissions remain unmanaged.
    unrepresented_buckets = sorted(set(current.buckets) - represented_buckets)
    for name in sorted(current.unmanaged_roles):
        if name in REGISTRY_MANAGED_ROLE_EXCLUSIONS:
            notes.append(f"registry-managed role {name!r}")
            continue
        if name in role_entries:
            notes.append(f"unmanaged role {name!r} collides with a managed role")
            continue
        entry = {CONFIG_UNMANAGED_KEY: True}
        registration_field = BUILTIN_BUCKET_REGISTRATION_FIELDS.get(name)
        if registration_field is not None and unrepresented_buckets:
            entry[registration_field] = unrepresented_buckets
        role_entries[name] = entry

    sso_notes, selectors, admin_roles, sso_default_role = _acl_sso_fields(
        current, set(role_entries)
    )
    notes.extend(sso_notes)

    settings_default_role = current.default_role_name
    if settings_default_role is not None:
        if settings_default_role in role_entries:
            role_entries[settings_default_role]["config.default_role"] = True
        else:
            notes.append(
                f"settings default role {settings_default_role!r} is not captured"
            )

    defaults_disagree = (
        current.sso_config_text is not None
        and not sso_notes
        and sso_default_role != settings_default_role
    )
    if defaults_disagree:
        notes.append(
            f"SSO default role {sso_default_role!r} differs from settings default "
            f"role {settings_default_role!r}; existing SSO left untouched"
        )

    # If any part of SSO is not representable, or its default differs from the
    # operative settings default, leave the complete server SSO document
    # unmanaged rather than emitting a partial, destructive rewrite.
    if not sso_notes and not defaults_disagree:
        for role_name, role_selectors in selectors.items():
            role_entries[role_name].update(role_selectors)
        for role_name in admin_roles:
            role_entries[role_name]["config.is_admin"] = True

    user_entries: dict[str, dict[str, Any]] = {}
    for user in sorted(current.users, key=lambda item: item.name):
        primary = getattr(getattr(user, "role", None), "name", None)
        if not primary:
            notes.append(f"user {user.name!r} has no primary role")
            continue
        extras = [
            role.name
            for role in (getattr(user, "extra_roles", None) or [])
            if role is not None
        ]
        is_admin = bool(getattr(user, "is_admin", False))
        if (
            omit_default_users
            and primary == current.default_role_name
            and not extras
            and not is_admin
        ):
            continue
        user_entry: dict[str, Any] = {"role": primary}
        if extras:
            user_entry["extra_roles"] = extras
        user_entry["admin"] = is_admin
        user_entries[user.name] = user_entry

    for title in sorted(set(current.unmanaged_policies) - referenced_policy_names):
        notes.append(f"unmanaged policy {title!r}")
    for name in sorted(set(current.managed_roles) & REGISTRY_MANAGED_ROLE_EXCLUSIONS):
        notes.append(f"registry-managed role {name!r}")
    for title in sorted(
        set(current.managed_policies) & REGISTRY_MANAGED_POLICY_EXCLUSIONS
    ):
        notes.append(f"registry-managed policy {title!r}")

    payload = {
        "policies": policy_entries,
        "roles": role_entries,
        "users": user_entries,
    }
    lines = [
        f"# quiltx ACL capture for {catalog}",
        f"# captured: {captured_on}",
        yaml.safe_dump(payload, sort_keys=False).rstrip(),
    ]
    risk_warnings = export_downgrade_warnings(current, "\n".join(lines))
    for warning in risk_warnings:
        notes.append(f"DOWNGRADE RISK: {warning}")
    if notes:
        lines.append("# not captured:")
        lines.extend(f"# - {note}" for note in _dedupe_preserve_order(notes))
    return "\n".join(lines) + "\n", risk_warnings


def _acl_bucket_fields(policy: Any) -> tuple[list[str], list[str], list[str]]:
    read: set[str] = set()
    read_write: set[str] = set()
    notes: list[str] = []
    for permission in getattr(policy, "permissions", None) or []:
        level = str(permission.level).split(".")[-1]
        if level == "READ_WRITE":
            read_write.add(permission.bucket)
        elif level == "READ":
            read.add(permission.bucket)
        else:
            notes.append(
                f"policy {policy.title!r} permission {permission.bucket!r} "
                f"has unsupported level {level!r}"
            )
    return sorted(read - read_write), sorted(read_write), notes


def _acl_sso_fields(
    current: CurrentState, captured_roles: set[str]
) -> tuple[list[str], dict[str, dict[str, list[str]]], set[str], str | None]:
    if current.sso_config_text is None:
        return [], {}, set(), None
    raw = yaml.safe_load(current.sso_config_text) or {}
    if not isinstance(raw, dict):
        return (
            ["SSO configuration is not a mapping; existing SSO left untouched"],
            {},
            set(),
            None,
        )

    notes: list[str] = []
    if raw.get("version") != "1.0" or raw.get("union_roles") is not True:
        notes.append("SSO version/union_roles settings are not representable")
    unknown_keys = set(raw) - {"version", "union_roles", "default_role", "mappings"}
    if unknown_keys:
        notes.append("SSO has unsupported fields: " + ", ".join(sorted(unknown_keys)))

    selectors: dict[str, dict[str, list[str]]] = {}
    admin_votes: dict[str, set[bool | None]] = {}
    for index, mapping in enumerate(raw.get("mappings") or []):
        decoded = _decode_acl_sso_mapping(mapping)
        if decoded is None:
            notes.append(f"SSO mapping {index + 1} is not representable")
            continue
        role_name, claim, value, admin = decoded
        if role_name not in captured_roles:
            notes.append(
                f"SSO mapping {index + 1} targets uncaptured role {role_name!r}"
            )
            continue
        key = f"sso.{claim}"
        selectors.setdefault(role_name, {}).setdefault(key, []).append(value)
        admin_votes.setdefault(role_name, set()).add(admin)

    admin_roles: set[str] = set()
    for role_name, votes in admin_votes.items():
        if votes == {True}:
            admin_roles.add(role_name)
        elif votes != {None}:
            notes.append(
                f"SSO mappings for role {role_name!r} have mixed or false admin votes"
            )

    default_role = raw.get("default_role")
    if default_role is not None:
        if not isinstance(default_role, str) or default_role not in captured_roles:
            notes.append(f"SSO default role {default_role!r} is not captured")
            default_role = None
        elif default_role not in selectors:
            notes.append(
                f"SSO default role {default_role!r} has no representable selector"
            )
            default_role = None
    return notes, selectors, admin_roles, default_role


def _decode_acl_sso_mapping(
    mapping: Any,
) -> tuple[str, str, str, bool | None] | None:
    if not isinstance(mapping, dict) or set(mapping) - {"schema", "roles", "admin"}:
        return None
    roles = mapping.get("roles")
    if not isinstance(roles, list) or len(roles) != 1 or not isinstance(roles[0], str):
        return None
    admin = mapping.get("admin")
    if admin is not None and not isinstance(admin, bool):
        return None
    schema = mapping.get("schema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return None
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or len(properties) != 1:
        return None
    claim, claim_schema = next(iter(properties.items()))
    if not isinstance(claim, str) or required != [claim]:
        return None
    value: Any = None
    if claim == "groups" and isinstance(claim_schema, dict):
        value = (claim_schema.get("contains") or {}).get("const")
        expected = _sso_claim_schema(claim, value) if isinstance(value, str) else None
    elif isinstance(claim_schema, dict):
        any_of = claim_schema.get("anyOf")
        value = any_of[0].get("const") if isinstance(any_of, list) and any_of else None
        expected = _sso_claim_schema(claim, value) if isinstance(value, str) else None
    else:
        expected = None
    if expected is None or claim_schema != expected:
        return None
    return roles[0], claim, value, admin


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
    sqs_client = session.client("sqs", region_name=region)
    lambda_client = session.client("lambda", region_name=region)
    data_account_id = str(session.client("sts").get_caller_identity()["Account"])

    plan = bucket_lib.build_bucket_preparation_plan(
        bucket,
        region,
        data_account_id,
        control_account_id=control_account_id,
        s3_client=s3_client,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )
    if plan.principals_before:
        # Two stacks can each list the same bucket in their ACL. Grants
        # accumulate (issue #102), so say which ones were kept.
        print(
            f"  bucket {bucket}: keeping existing grants for "
            f"{', '.join(plan.principals_before)}",
            file=sys.stderr,
        )
    if plan.principals_removed:
        print(
            f"  ! bucket {bucket}: removing grants for "
            f"{', '.join(plan.principals_removed)}",
            file=sys.stderr,
        )
    bucket_lib.apply_bucket_preparation(
        plan,
        s3_client=s3_client,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )
    stack.admin.buckets.add(
        name=bucket, title=bucket, sns_notification_arn=plan.sns_topic_arn
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


def _apply_user_updates(
    stack: stack_lib.Catalog,
    updates: list[AclUserUpdate],
    failed_roles: set[str],
    *,
    verbose: bool,
    role_updates_blocked: bool = False,
) -> list[str]:
    """Apply configured existing-user changes without creating or deleting users."""
    warnings: list[str] = []
    for update in updates:
        role_assignment_failed = False
        if update.role_changed:
            unavailable = failed_roles & {update.role, *update.extra_roles}
            if role_updates_blocked:
                role_assignment_failed = True
                detail = "SSO config could not be cleared"
                warnings.append(
                    f"User '{update.name}' role assignment skipped: {detail}"
                )
                print(f"  ! user {update.name}: {detail}", file=sys.stderr)
            elif unavailable:
                role_assignment_failed = True
                detail = "desired role creation failed: " + ", ".join(
                    sorted(unavailable)
                )
                warnings.append(
                    f"User '{update.name}' role assignment skipped: {detail}"
                )
                print(f"  ! user {update.name}: {detail}", file=sys.stderr)
            else:
                _print_apply_step(f"update user {update.name} roles", verbose=verbose)
                try:
                    stack.admin.users.set_role(
                        update.name,
                        update.role,
                        extra_roles=list(update.extra_roles) or None,
                        append=False,
                    )
                    print(f"  ~ user {update.name} (roles)")
                except Exception as exc:
                    role_assignment_failed = True
                    detail = format_exception(exc)
                    warnings.append(
                        f"User '{update.name}' roles could not be updated: {detail}"
                    )
                    print(f"  ! user {update.name}: {detail}", file=sys.stderr)

        if update.admin_changed:
            if update.admin and role_assignment_failed:
                detail = "role assignment failed"
                warnings.append(
                    f"User '{update.name}' admin elevation skipped: {detail}"
                )
                print(f"  ! user {update.name}: {detail}", file=sys.stderr)
                continue
            _print_apply_step(f"update user {update.name} admin", verbose=verbose)
            try:
                stack.admin.users.set_admin(update.name, bool(update.admin))
                print(f"  ~ user {update.name} (admin={update.admin})")
            except Exception as exc:
                detail = format_exception(exc)
                warnings.append(
                    f"User '{update.name}' admin status could not be updated: {detail}"
                )
                print(f"  ! user {update.name}: {detail}", file=sys.stderr)
    return warnings


def _sso_config_declares_default(
    diff: AclDiff, current: CurrentState, role_name: str
) -> bool:
    """True if the effective SSO config carries role_name as its default.

    The registry locks the settings-level default role while an SSO config
    exists and password signup is disabled (SsoConfigConflict); in that state
    the SSO config's own ``default_role`` is what governs, so a conflict is
    only a problem when that config names a different role.
    """
    text = diff.sso_config_text if diff.sso_needs_update else current.sso_config_text
    if not text:
        return False
    try:
        payload = yaml.safe_load(text)
    except yaml.YAMLError:
        return False
    return isinstance(payload, dict) and payload.get("default_role") == role_name


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
    bucket_failures: list[BucketRegistrationFailure] = []
    failed_roles: set[str] = set()
    default_policy_skips: dict[str, list[str]] = {}

    graphql_only_buckets = {
        bucket
        for bucket in diff.buckets_to_add
        if no_preflight or bucket in diff.no_preflight_buckets
    }

    control_account_id: str | None = None
    if set(diff.buckets_to_add) - graphql_only_buckets:
        try:
            payload = stack.payload
            if payload and payload.get("account_id"):
                control_account_id = str(payload["account_id"])
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(f"Could not load control account for bucket add: {exc}")

    for bucket in diff.buckets_to_add:
        try:
            _print_apply_step(f"add bucket {bucket}", verbose=verbose)
            if bucket in graphql_only_buckets:
                from quiltx import bucket as bucket_lib

                bucket_lib.add_bucket_without_preflight(stack, bucket, title=bucket)
            elif control_account_id is None:
                raise ValueError(
                    "control account metadata is required for AWS preparation; "
                    "refresh the catalog stack cache or use --no-preflight explicitly"
                )
            else:
                _register_bucket_with_retry(
                    stack,
                    bucket,
                    control_account_id,
                    assume_yes=assume_yes,
                )
            print(f"  + bucket {bucket}")
        except Exception as exc:
            detail = format_exception(exc)
            failed_buckets.add(bucket)
            bucket_failures.append(
                BucketRegistrationFailure(name=bucket, reason=detail)
            )
            warnings.append(f"Bucket '{bucket}' was not registered: {detail}")
            print(f"  ! bucket {bucket}: {detail}", file=sys.stderr)

    if bucket_failures:
        print_bucket_registration_failures(bucket_failures, stream=sys.stderr)

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
            # A registry mutation may persist successfully and still return a
            # generic 500. Refetch so dependent roles can use the real policy
            # ID instead of being skipped until a second run.
            try:
                persisted = next(
                    (
                        item
                        for item in stack.admin.policies.list()
                        if getattr(item, "title", None) == policy.title
                        and bool(getattr(item, "managed", False))
                    ),
                    None,
                )
            except Exception:
                persisted = None
            if persisted is None:
                continue
            known_policies[policy.title] = persisted
            print(f"  ~ policy {policy.title} (found after failed create)")
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
        # Quilt3 resolves update references by trying policy(id:) first. Never
        # pass a title there: registry policy IDs are UUIDs, and a title causes
        # a server-side UUID parse failure before quilt3 can try its title list.
        existing = known_policies.get(policy.title)
        if existing is None:
            detail = "policy not found in the fetched current state"
            warnings.append(f"Policy '{policy.title}' could not be updated: {detail}")
            print(f"  ! policy {policy.title}: {detail}", file=sys.stderr)
            continue
        policy_ref = str(existing.id)
        existing_role_ids = [role.id for role in getattr(existing, "roles", []) or []]
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
            missing = exc.args[0]
            warnings.append(f"Role '{role.name}' skipped: unknown policy {missing!r}")
            print(f"  ! role {role.name}: unknown policy {missing!r}", file=sys.stderr)
            if missing in diff.default_policy_titles:
                default_policy_skips.setdefault(str(missing), []).append(role.name)
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
            missing = exc.args[0]
            warnings.append(f"Role '{role.name}' skipped: unknown policy {missing!r}")
            print(f"  ! role {role.name}: unknown policy {missing!r}", file=sys.stderr)
            if missing in diff.default_policy_titles:
                default_policy_skips.setdefault(str(missing), []).append(role.name)
            continue
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"Role '{role.name}' could not be updated: {detail}")
            print(f"  ! role {role.name}: {detail}", file=sys.stderr)
            continue
        print(f"  ~ role {role.name}")

    if default_policy_skips:
        # Said once, before the cascade into the default role and every user
        # role assignment adds its own lines.
        print_default_policy_failures(default_policy_skips, stream=sys.stderr)
        warnings.extend(
            default_policy_failure_message(title, roles)
            for title, roles in default_policy_skips.items()
        )

    if diff.default_role_needs_update and diff.default_role_name is not None:
        default_role_name = diff.default_role_name
        if default_role_name in failed_roles:
            detail = "desired role creation failed"
            warnings.append(
                f"Default role '{default_role_name}' could not be updated: {detail}"
            )
            print(f"  ! default role {default_role_name}: {detail}", file=sys.stderr)
        else:
            _print_apply_step(f"set default role {default_role_name}", verbose=verbose)
            try:
                # Resolve the id ourselves: set_default(name) falls back to a
                # role(id: <name>) lookup, which registries answer with a 500
                # (UUID primary-key column). Re-list so roles created earlier
                # in this apply are visible.
                resolved_role = next(
                    (
                        r
                        for r in stack.admin.roles.list()
                        if r.name == default_role_name
                    ),
                    None,
                )
                stack.admin.roles.set_default(
                    default_role_name if resolved_role is None else resolved_role.id
                )
            except quilt3_admin_exceptions.RoleSsoConfigConflictError:
                if _sso_config_declares_default(diff, current, default_role_name):
                    print(
                        f"  = default role {default_role_name} is governed by the "
                        "SSO config; settings-level default left unchanged"
                    )
                else:
                    detail = (
                        "the registry locks the settings-level default role while "
                        "an SSO config exists and password signup is disabled, and "
                        f"the SSO config does not name '{default_role_name}' as its "
                        "default"
                    )
                    warnings.append(
                        f"Default role '{default_role_name}' could not be updated: {detail}"
                    )
                    print(
                        f"  ! default role {default_role_name}: {detail}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                detail = format_exception(exc)
                warnings.append(
                    f"Default role '{default_role_name}' could not be updated: {detail}"
                )
                print(
                    f"  ! default role {default_role_name}: {detail}",
                    file=sys.stderr,
                )
            else:
                print(f"  ~ default role {default_role_name}")

    user_role_updates = [
        update for update in diff.users_to_update if update.role_changed
    ]
    applicable_user_role_updates = [
        update
        for update in user_role_updates
        if not failed_roles.intersection({update.role, *update.extra_roles})
    ]
    sso_cleared_for_user_roles = False
    role_updates_blocked = False
    if applicable_user_role_updates and current.sso_config_text is not None:
        clear_warnings = clear_sso_config(stack, verbose=verbose)
        warnings.extend(clear_warnings)
        sso_cleared_for_user_roles = not clear_warnings
        role_updates_blocked = bool(clear_warnings)

    if diff.users_to_update:
        warnings.extend(
            _apply_user_updates(
                stack,
                diff.users_to_update,
                failed_roles,
                verbose=verbose,
                role_updates_blocked=role_updates_blocked,
            )
        )

    sso_text_to_restore = current.sso_config_text
    sso_update_succeeded = False
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
                sso_update_succeeded = True
                sso_text_to_restore = pruned_text
                prefix = "+" if diff.sso_is_create else "~"
                print(f"  {prefix} sso config")

    if sso_cleared_for_user_roles and not sso_update_succeeded:
        _print_apply_step("restore sso config after user updates", verbose=verbose)
        try:
            stack.admin.sso_config.set(sso_text_to_restore)
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(
                f"SSO config could not be restored after user updates: {detail}"
            )
            print(f"  ! sso config: {detail}", file=sys.stderr)
        else:
            print("  ~ sso config (restored after user updates)")

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
        # Name collisions with unmanaged policies are intentionally skipped by
        # reconciliation and must never be escalated into delete/reset recovery.
        if title in current.unmanaged_policies:
            continue
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
    policy = current.managed_policies.get(policy_title)
    if policy is None:
        raise ValueError(
            f"Policy '{policy_title}' was not present in the fetched current state"
        )
    return str(policy.id)


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
    # A missing policy is the normal failed-create drift case. There is
    # nothing destructive to reset; the caller's reapply will create it.
    if title not in current.managed_policies:
        return warnings, user_snapshot
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
            stack.admin.roles.delete(_role_ref(role_name, current))
            print(f"  - role {role_name}")
        except Exception as exc:
            detail = format_exception(exc)
            warnings.append(f"Role '{role_name}' could not be deleted: {detail}")
            print(f"  ! role {role_name}: {detail}", file=sys.stderr)
        finally:
            deleted.add(role_name)
    try:
        policy_ref = _policy_ref(title, current)
        _print_apply_step(f"delete policy {title}", verbose=verbose)
        stack.admin.policies.delete(policy_ref)
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
        if not policy.synthesize:
            continue
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
    unmanaged_role_names: set[str] = set()
    for role in config.roles.values():
        if role.unmanaged:
            # Reference only: no policies, no role_updates entry, so the role is
            # never created, updated, or deleted. SSO selectors and the default
            # role may still point at it.
            unmanaged_role_names.add(role.name)
            static_roles.append(
                _ResolvedStaticRole(
                    name=role.name,
                    sso=role.sso,
                    policy_titles=[],
                    is_admin=role.is_admin,
                    default_role=role.default_role,
                    inline_policy_title=None,
                    unmanaged=True,
                )
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
            continue

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

    default_policy_titles = [
        policy.name for policy in config.policies if policy.default_policy
    ]
    if default_policy_titles:
        # Composed after the ladder so cumulative_policy_titles stays the only
        # input to _synthesized_role_name: a floor adds permissions to a role,
        # never a rung to its name. Appending last and deduping leaves a role
        # that already lists the policy unchanged, so a replay stays a no-op.
        role_updates = {
            name: RoleUpdate(
                name=name,
                policy_titles=_dedupe_preserve_order(
                    [*update.policy_titles, *default_policy_titles]
                ),
            )
            for name, update in role_updates.items()
        }
        # The verbose listing reads these, and it must show what gets applied.
        synthesized_roles = [
            replace(role, policy_titles=list(role_updates[role.name].policy_titles))
            for role in synthesized_roles
        ]
        static_roles = [
            (
                role
                if role.unmanaged
                else replace(
                    role, policy_titles=list(role_updates[role.name].policy_titles)
                )
            )
            for role in static_roles
        ]
        if unmanaged_role_names:
            warnings.append(
                f"Default policies {', '.join(default_policy_titles)} do not reach "
                f"unmanaged roles {', '.join(sorted(unmanaged_role_names))}: quiltx "
                "never modifies an unmanaged role's IAM permissions. A user whose "
                "only role is unmanaged does not receive the default policies and "
                "must also match a managed role's selector to get them."
            )

    return _DesiredAclState(
        policy_updates=policy_updates,
        synthesized_roles=synthesized_roles,
        static_roles=static_roles,
        role_updates=role_updates,
        sso_mappings=sso_mappings,
        default_role_name=default_role_name,
        warnings=warnings,
        unmanaged_role_names=frozenset(unmanaged_role_names),
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
        allowed_keys.update(
            {POLICY_ROLE_NAME_KEY, CONFIG_DEFAULT_POLICY_KEY, CONFIG_SYNTHESIZE_KEY}
        )
    if section == "roles":
        allowed_keys.update({CONFIG_POLICIES_KEY, CONFIG_UNMANAGED_KEY})
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
        hint += (
            f" Explicit roles also support the magic {CONFIG_POLICIES_KEY} and "
            f"{CONFIG_UNMANAGED_KEY} keys."
        )
    if section == "policies":
        hint += (
            f" Policies also support the magic {POLICY_ROLE_NAME_KEY}, "
            f"{CONFIG_DEFAULT_POLICY_KEY}, and {CONFIG_SYNTHESIZE_KEY} keys."
        )
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


def _parse_acl_entry(
    value: dict[str, Any],
    field_name: str,
    *,
    require_sso_selector: bool = True,
) -> _ParsedAclEntry:
    sso = _coerce_sso_selectors(value, field_name, required=require_sso_selector)
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
    synthesized_policies = [policy for policy in policies if policy.synthesize]
    for previous, current in zip(synthesized_policies, synthesized_policies[1:]):
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
        if not policy.synthesize:
            continue
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
        if policy.default_policy:
            print("    default_policy: true")

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

    updated_users = {user.name for user in diff.users_to_update}
    current_user_names = (
        {user.name for user in current.users} if current is not None else set()
    )
    for name, user in desired.users.items():
        # A key may be an email, so report the username the diff acted on.
        server_name = diff.resolved_user_names.get(name, name)
        prefix = (
            "~"
            if server_name in updated_users
            else "=" if current is None or server_name in current_user_names else "?"
        )
        label = name if server_name == name else f"{name} -> {server_name}"
        print(f"{prefix} user {label}")
        print(f"    role: {user.role}")
        print(f"    extra_roles: {', '.join(user.extra_roles) or '(none)'}")
        if user.admin is not None:
            print(f"    admin: {str(user.admin).lower()}")

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
    value: dict[str, Any], section_name: str, *, required: bool = True
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
    if required and not sso:
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
