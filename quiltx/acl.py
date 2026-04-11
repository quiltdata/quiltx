"""Declarative ACL reconciliation for Quilt stacks."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from quiltx.config import auto_login
from quilt3.admin import buckets as admin_buckets
from quilt3.admin import policies as admin_policies
from quilt3.admin import roles as admin_roles
from quilt3.admin import sso_config as admin_sso_config
from quilt3.admin.types import Permission


@dataclass(frozen=True)
class AclBucketPolicy:
    name: str
    read: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AclRole:
    name: str
    bucket_policies: list[str] = field(default_factory=list)
    default: bool = False


@dataclass(frozen=True)
class AclSsoMapping:
    match: dict[str, str]
    roles: list[str]
    admin: bool = False


@dataclass(frozen=True)
class AclConfig:
    bucket_policies: dict[str, AclBucketPolicy]
    roles: dict[str, AclRole]
    sso: list[AclSsoMapping]
    default_role_name: str | None = None


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


def parse_acl_config(path: str | Path) -> AclConfig:
    """Load and validate ACL configuration from YAML."""
    raw = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError("ACL config must be a mapping at the top level")

    raw_bucket_policies = raw.get("bucket_policies") or {}
    raw_roles = raw.get("roles") or {}
    raw_sso = raw.get("sso") or []

    if not isinstance(raw_bucket_policies, dict):
        raise ValueError("'bucket_policies' must be a mapping")
    if not isinstance(raw_roles, dict):
        raise ValueError("'roles' must be a mapping")
    if not isinstance(raw_sso, list):
        raise ValueError("'sso' must be a list")

    bucket_policies: dict[str, AclBucketPolicy] = {}
    for name, value in raw_bucket_policies.items():
        if not isinstance(name, str):
            raise ValueError("Bucket policy names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Bucket policy '{name}' must be a mapping")
        read = _coerce_string_list(
            value.get("read", []), f"bucket_policies.{name}.read"
        )
        read_write = _coerce_string_list(
            value.get("read_write", []), f"bucket_policies.{name}.read_write"
        )
        bucket_policies[name] = AclBucketPolicy(
            name=name,
            read=sorted(set(read)),
            read_write=sorted(set(read_write)),
        )

    roles: dict[str, AclRole] = {}
    default_roles: list[str] = []
    for name, value in raw_roles.items():
        if not isinstance(name, str):
            raise ValueError("Role names must be strings")
        if not isinstance(value, dict):
            raise ValueError(f"Role '{name}' must be a mapping")
        policy_names = _coerce_string_list(
            value.get("bucket_policies", []), f"roles.{name}.bucket_policies"
        )
        missing = sorted(set(policy_names) - bucket_policies.keys())
        if missing:
            raise ValueError(
                f"Role '{name}' references unknown bucket policies: {', '.join(missing)}"
            )
        default = value.get("default", False)
        if not isinstance(default, bool):
            raise ValueError(f"roles.{name}.default must be a boolean")
        if default:
            default_roles.append(name)
        roles[name] = AclRole(name=name, bucket_policies=policy_names, default=default)

    if len(default_roles) > 1:
        raise ValueError(
            "Only one role may set default: true; found "
            + ", ".join(sorted(default_roles))
        )

    sso: list[AclSsoMapping] = []
    for index, value in enumerate(raw_sso):
        if not isinstance(value, dict):
            raise ValueError(f"sso[{index}] must be a mapping")
        match = value.get("match")
        if not isinstance(match, dict) or not match:
            raise ValueError(f"sso[{index}].match must be a non-empty mapping")
        normalized_match: dict[str, str] = {}
        for key, match_value in match.items():
            if not isinstance(key, str):
                raise ValueError(f"sso[{index}].match keys must be strings")
            if not isinstance(match_value, str):
                raise ValueError(f"sso[{index}].match.{key} must be a string")
            normalized_match[key] = match_value

        mapping_roles = _coerce_string_list(
            value.get("roles", []), f"sso[{index}].roles"
        )
        if not mapping_roles:
            raise ValueError(f"sso[{index}].roles must not be empty")
        missing_roles = sorted(set(mapping_roles) - roles.keys())
        if missing_roles:
            raise ValueError(
                f"sso[{index}] references unknown roles: {', '.join(missing_roles)}"
            )

        admin = value.get("admin", False)
        if not isinstance(admin, bool):
            raise ValueError(f"sso[{index}].admin must be a boolean")

        sso.append(
            AclSsoMapping(match=normalized_match, roles=mapping_roles, admin=admin)
        )

    default_role_name = default_roles[0] if default_roles else None
    return AclConfig(
        bucket_policies=bucket_policies,
        roles=roles,
        sso=sso,
        default_role_name=default_role_name,
    )


def all_buckets(config: AclConfig) -> set[str]:
    """Return all buckets referenced by the ACL config."""
    result: set[str] = set()
    for policy in config.bucket_policies.values():
        result.update(policy.read)
        result.update(policy.read_write)
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
    diff = AclDiff()
    diff.buckets_to_add = sorted(all_buckets(desired) - current.buckets.keys())

    for name, bucket_policy in desired.bucket_policies.items():
        desired_permissions = _permissions_for_policy(bucket_policy)
        if name in current.unmanaged_policies:
            diff.warnings.append(
                f"Policy '{name}' already exists as unmanaged; skipping managed policy update."
            )
            continue

        current_policy = current.managed_policies.get(name)
        if current_policy is None:
            diff.policies_to_create.append(
                PolicyUpdate(title=name, permissions=desired_permissions)
            )
            continue

        if _canonical_permissions(current_policy.permissions) != _canonical_permissions(
            desired_permissions
        ):
            diff.policies_to_update.append(
                PolicyUpdate(title=name, permissions=desired_permissions)
            )

    diff.policies_to_delete = sorted(
        title
        for title in current.managed_policies.keys()
        if title not in desired.bucket_policies
    )

    for name, role in desired.roles.items():
        if name in current.unmanaged_roles:
            diff.warnings.append(
                f"Role '{name}' already exists as unmanaged; skipping managed role update."
            )
            continue

        current_role = current.managed_roles.get(name)
        desired_policy_titles = sorted(role.bucket_policies)
        if current_role is None:
            diff.roles_to_create.append(
                RoleUpdate(name=name, policy_titles=desired_policy_titles)
            )
            continue

        current_policy_titles = sorted(policy.title for policy in current_role.policies)
        if current_policy_titles != desired_policy_titles:
            diff.roles_to_update.append(
                RoleUpdate(name=name, policy_titles=desired_policy_titles)
            )

    current_sso_roles = _extract_sso_roles(current.sso_config_text)
    diff.roles_to_delete = sorted(
        name
        for name in current.managed_roles.keys()
        if name not in desired.roles
        and name not in current_sso_roles
        and name != current.default_role_name
    )

    for name in sorted(current.managed_roles.keys() - set(desired.roles)):
        if name in current_sso_roles:
            diff.warnings.append(
                f"Role '{name}' is still referenced by the current SSO config; skipping delete."
            )
        elif name == current.default_role_name:
            diff.warnings.append(
                f"Role '{name}' is the current default role; skipping delete."
            )

    desired_sso_text = (
        build_sso_config(desired.sso, default_role_name=desired.default_role_name)
        if desired.sso
        else None
    )
    if desired_sso_text is not None and not _same_yaml(
        current.sso_config_text, desired_sso_text
    ):
        diff.sso_config_text = desired_sso_text
        diff.sso_is_create = current.sso_config_text is None
        diff.sso_needs_update = True

    return diff


def build_sso_config(
    mappings: list[AclSsoMapping], *, default_role_name: str | None = None
) -> str:
    """Translate simplified SSO mappings to Quilt's schema-based YAML."""
    payload: dict[str, Any] = {
        "version": "1.0",
        "mappings": [],
    }
    if default_role_name is not None:
        payload["default_role"] = default_role_name
    for mapping in mappings:
        properties: dict[str, Any] = {}
        required: list[str] = []
        for key, value in mapping.match.items():
            if key == "groups":
                properties[key] = {
                    "type": "array",
                    "contains": {"const": value},
                }
            else:
                properties[key] = {"const": value}
            required.append(key)

        payload["mappings"].append(
            {
                "schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
                "roles": list(mapping.roles),
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
        if verbose:
            _print_permissions(policy.permissions)
    for policy in diff.policies_to_update:
        print(f"~ policy {policy.title}")
        if verbose:
            _print_permissions(policy.permissions)
    for title in diff.policies_to_delete:
        print(f"- policy {title}")

    for role in diff.roles_to_create:
        print(f"+ role {role.name}")
        if verbose:
            print(f"    policies: {', '.join(role.policy_titles)}")
    for role in diff.roles_to_update:
        print(f"~ role {role.name}")
        if verbose:
            print(f"    policies: {', '.join(role.policy_titles)}")
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


def apply_acl(
    diff: AclDiff, current: CurrentState, *, verbose: bool = False
) -> list[str]:
    """Apply ACL changes. Returns any runtime warnings."""
    warnings = list(diff.warnings)
    failed_buckets: set[str] = set()

    for bucket in diff.buckets_to_add:
        try:
            _print_apply_step(f"add bucket {bucket}", verbose=verbose)
            admin_buckets.add(bucket, bucket)
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
            warnings.append(
                f"Policy '{policy.title}' could not be created{hint}: {exc}"
            )
            print(f"  ! policy {policy.title}: {exc}", file=sys.stderr)
            continue
        known_policies[policy.title] = created
        print(f"  + policy {policy.title}")
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
            warnings.append(
                f"Policy '{policy.title}' could not be updated{hint}: {exc}"
            )
            print(f"  ! policy {policy.title}: {exc}", file=sys.stderr)
            continue
        known_policies[policy.title] = updated
        print(f"  ~ policy {policy.title}")

    for role in diff.roles_to_create:
        _print_apply_step(f"create role {role.name}", verbose=verbose)
        try:
            policy_ids = _resolve_policy_ids(role.policy_titles, known_policies)
            admin_roles.create_managed(role.name, policies=policy_ids)
        except KeyError as exc:
            msg = f"Role '{role.name}' skipped: unknown policy {exc.args[0]!r}"
            warnings.append(msg)
            print(
                f"  ! role {role.name}: unknown policy {exc.args[0]!r}", file=sys.stderr
            )
            continue
        except Exception as exc:
            warnings.append(f"Role '{role.name}' could not be created: {exc}")
            print(f"  ! role {role.name}: {exc}", file=sys.stderr)
            continue
        print(f"  + role {role.name}")

    for role in diff.roles_to_update:
        _print_apply_step(f"update role {role.name}", verbose=verbose)
        try:
            policy_ids = _resolve_policy_ids(role.policy_titles, known_policies)
            admin_roles.update_managed(role.name, name=role.name, policies=policy_ids)
        except KeyError as exc:
            msg = f"Role '{role.name}' skipped: unknown policy {exc.args[0]!r}"
            warnings.append(msg)
            print(
                f"  ! role {role.name}: unknown policy {exc.args[0]!r}", file=sys.stderr
            )
            continue
        except Exception as exc:
            warnings.append(f"Role '{role.name}' could not be updated: {exc}")
            print(f"  ! role {role.name}: {exc}", file=sys.stderr)
            continue
        print(f"  ~ role {role.name}")

    if diff.sso_needs_update and diff.sso_config_text is not None:
        _print_apply_step("update sso config", verbose=verbose)
        try:
            admin_sso_config.set(diff.sso_config_text)
        except Exception as exc:
            warnings.append(f"SSO config could not be updated: {exc}")
            print(f"  ! sso config: {exc}", file=sys.stderr)
        else:
            prefix = "+" if diff.sso_is_create else "~"
            print(f"  {prefix} sso config")

    for role_name in diff.roles_to_delete:
        try:
            _print_apply_step(f"delete role {role_name}", verbose=verbose)
            admin_roles.delete(role_name)
            print(f"  - role {role_name}")
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(f"Role '{role_name}' could not be deleted: {exc}")

    for policy_title in diff.policies_to_delete:
        try:
            _print_apply_step(f"delete policy {policy_title}", verbose=verbose)
            admin_policies.delete(policy_title)
            print(f"  - policy {policy_title}")
        except Exception as exc:  # pragma: no cover - external API surface
            warnings.append(f"Policy '{policy_title}' could not be deleted: {exc}")

    return warnings


def _print_permissions(permissions: list[Permission]) -> None:
    for perm in permissions:
        level = perm.level.name if hasattr(perm.level, "name") else str(perm.level)
        print(f"    {level}: {perm.bucket}")


def _print_apply_step(message: str, *, verbose: bool) -> None:
    print(f"-> {message}")


def _print_verbose_state(
    diff: AclDiff, desired: AclConfig, current: CurrentState | None
) -> None:
    print("Desired ACL:")

    changed_buckets = set(diff.buckets_to_add)
    for bucket in sorted(all_buckets(desired)):
        prefix = "+" if bucket in changed_buckets else "="
        print(f"{prefix} bucket {bucket}")

    created_policies = {policy.title for policy in diff.policies_to_create}
    updated_policies = {policy.title for policy in diff.policies_to_update}
    for title, policy in desired.bucket_policies.items():
        if title in created_policies:
            prefix = "+"
        elif title in updated_policies:
            prefix = "~"
        else:
            prefix = "="
        print(f"{prefix} policy {title}")
        _print_permissions(_permissions_for_policy(policy))

    created_roles = {role.name for role in diff.roles_to_create}
    updated_roles = {role.name for role in diff.roles_to_update}
    for name, role in desired.roles.items():
        if name in created_roles:
            prefix = "+"
        elif name in updated_roles:
            prefix = "~"
        else:
            prefix = "="
        print(f"{prefix} role {name}")
        print(f"    policies: {', '.join(role.bucket_policies) or '(none)'}")
        if role.default:
            print("    default: true")

    if desired.sso:
        prefix = (
            "+"
            if diff.sso_is_create and diff.sso_needs_update
            else "~" if diff.sso_needs_update else "="
        )
        print(f"{prefix} sso config")
        sso_text = (
            diff.sso_config_text
            if diff.sso_config_text is not None
            else build_sso_config(
                desired.sso, default_role_name=desired.default_role_name
            )
        )
        for line in sso_text.rstrip().splitlines():
            print(f"    {line}")
    elif current is not None and current.sso_config_text:
        print("= no sso config requested")


def _coerce_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"'{field_name}' must be a list")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"'{field_name}' entries must all be strings")
    return list(value)


def _permissions_for_policy(policy: AclBucketPolicy) -> list[Permission]:
    permissions = [Permission.read(bucket) for bucket in sorted(set(policy.read))]
    permissions.extend(
        Permission.read_write(bucket) for bucket in sorted(set(policy.read_write))
    )
    return permissions


def _policy_uses_buckets(permissions: list[Permission], buckets: set[str]) -> set[str]:
    """Return the subset of *buckets* referenced by *permissions*."""
    return {p.bucket for p in permissions} & buckets


def _canonical_permissions(permissions: list[Permission]) -> list[tuple[str, str]]:
    return sorted(
        (permission.bucket, str(permission.level)) for permission in permissions
    )


def _same_yaml(left: str | None, right: str | None) -> bool:
    return yaml.safe_load(left or "") == yaml.safe_load(right or "")


def _resolve_policy_ids(
    policy_titles: list[str], known_policies: dict[str, Any]
) -> list[str]:
    return [known_policies[title].id for title in policy_titles]


def _extract_sso_roles(config_text: str | None) -> set[str]:
    if not config_text:
        return set()
    loaded = yaml.safe_load(config_text) or {}
    if not isinstance(loaded, dict):
        return set()

    roles = set()
    default_role = loaded.get("default_role")
    if isinstance(default_role, str):
        roles.add(default_role)

    mappings = loaded.get("mappings") or []
    if isinstance(mappings, list):
        for mapping in mappings:
            if isinstance(mapping, dict):
                mapping_roles = mapping.get("roles") or []
                if isinstance(mapping_roles, list):
                    roles.update(
                        role for role in mapping_roles if isinstance(role, str)
                    )
    return roles


def with_default_role(config: AclConfig, default_role_name: str | None) -> AclConfig:
    """Return a copy of config with the selected default role name."""
    return replace(config, default_role_name=default_role_name)
