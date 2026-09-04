"""Tests for declarative stack ACL reconciliation."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from quilt3.admin import exceptions as quilt3_admin_exceptions
from quilt3.admin.types import BucketPermissionLevel, Permission

from quiltx import acl
from quiltx.tools.catalog import acl as acl_tool

from tests.conftest import make_fake_catalog


@dataclass
class FakePolicySummary:
    id: str
    title: str


@dataclass
class FakePolicy:
    id: str
    title: str
    managed: bool
    permissions: list[Any]
    roles: list[Any]


@dataclass
class FakeRole:
    id: str
    name: str
    policies: list[Any] | None
    permissions: list[Any]
    typename__: str = "ManagedRole"


@dataclass
class FakeBucket:
    name: str
    title: str


def _fake_stack(
    *,
    payload: dict[str, Any] | None = None,
    buckets: Any = None,
    policies: Any = None,
    roles: Any = None,
    sso_config: Any = None,
    users: Any = None,
) -> Any:
    return make_fake_catalog(
        "catalog",
        payload=payload,
        buckets=buckets,
        policies=policies,
        roles=roles,
        sso_config=sso_config,
        users=users,
    )


def _install_acl_tool_stack(monkeypatch, stack: Any | None = None) -> Any:
    fake_stack = stack or _fake_stack()
    monkeypatch.setattr(
        acl_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: fake_stack,
    )
    monkeypatch.setattr(acl_tool.stack_lib, "current_stack_header", lambda _stack: None)
    return fake_stack


def test_parse_acl_config_accepts_minimal_valid_config(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles: {}
""")

    config = acl.parse_acl_config(config_path)

    assert [policy.name for policy in config.policies] == ["public"]
    assert config.policies[0].sso == {"groups": ["Everyone"]}
    assert config.roles == {}


def test_parse_acl_config_accepts_simpler_stack_acl_example() -> None:
    config = acl.parse_acl_config(Path("stack-acl.example.yaml"))

    assert [policy.name for policy in config.policies] == ["public", "internal"]
    assert config.roles["exec"].policies == ["public", "internal"]
    assert config.roles["exec"].is_admin is True


def test_parse_acl_config_rejects_unknown_top_level_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies: {}
roles: {}
groups: {}
""")

    with pytest.raises(ValueError, match="Unknown top-level ACL keys"):
        acl.parse_acl_config(config_path)


def test_parse_acl_config_rejects_unknown_policy_and_role_fields(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text("""
policies:
  exec:
    sso.groups: [Everyone]
    config.policies: [public]
roles: {}
""")
    with pytest.raises(ValueError) as policy_error:
        acl.parse_acl_config(policy_path)

    policy_message = str(policy_error.value)
    assert "Unknown ACL fields in policies.exec" in policy_message
    assert "config.policies" in policy_message
    assert "only valid under top-level 'roles:'" in policy_message
    assert (
        "Supported ACL entry fields are buckets.read, buckets.read_write, "
        "config.default_role, config.is_admin" in policy_message
    )

    role_path = tmp_path / "role.yml"
    role_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
roles:
  exec:
    sso.users: [ernest@example.com]
    config.policies: [public]
    unknown: true
""")
    with pytest.raises(ValueError) as role_error:
        acl.parse_acl_config(role_path)

    role_message = str(role_error.value)
    assert "Unknown ACL fields in roles.exec" in role_message
    assert "unknown" in role_message
    assert "sso.users" not in role_message
    assert "sso.<claim>" in role_message
    assert (
        "Explicit roles also support the magic config.policies and "
        "config.unmanaged keys" in role_message
    )


def test_parse_acl_config_accepts_arbitrary_sso_claims(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
  sales:
    sso.department: [Sales]
roles:
  owner:
    sso.email: [owner@example.com]
    config.policies: [public]
""")

    config = acl.parse_acl_config(config_path)

    assert config.policies[1].sso == {"department": ["Sales"]}
    assert config.roles["owner"].sso == {"email": ["owner@example.com"]}


def test_parse_acl_config_accepts_user_policy_after_group_policy(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
  exec:
    sso.users: [ernest@quilt.bio]
roles: {}
""")

    config = acl.parse_acl_config(config_path)

    assert config.policies[1].sso == {"users": ["ernest@quilt.bio"]}


def test_parse_acl_config_rejects_non_list_groups_and_non_bool_flags(
    tmp_path: Path,
) -> None:
    groups_path = tmp_path / "groups.yml"
    groups_path.write_text("""
policies:
  public:
    sso.groups: Everyone
roles: {}
""")
    with pytest.raises(ValueError, match="policies.public.sso.groups"):
        acl.parse_acl_config(groups_path)

    admin_path = tmp_path / "admin.yml"
    admin_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
roles:
  exec:
    sso.groups: [Executives]
    config.is_admin: "yes"
""")
    with pytest.raises(ValueError, match="roles.exec.config.is_admin"):
        acl.parse_acl_config(admin_path)

    default_path = tmp_path / "default.yml"
    default_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: "yes"
roles: {}
""")
    with pytest.raises(ValueError, match="policies.public.config.default_role"):
        acl.parse_acl_config(default_path)

    role_default_path = tmp_path / "role_default.yml"
    role_default_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
roles:
  exec:
    sso.groups: [Executives]
    config.default_role: "yes"
""")
    with pytest.raises(ValueError, match="roles.exec.config.default_role"):
        acl.parse_acl_config(role_default_path)


def test_parse_acl_config_rejects_unknown_static_role_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
roles:
  exec:
    sso.groups: [Executives]
    config.policies: [missing]
""")

    with pytest.raises(ValueError, match="unknown policies"):
        acl.parse_acl_config(config_path)


def test_parse_acl_config_rejects_missing_or_multiple_sso_defaults(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
  internal:
    sso.groups: [Everyone]
roles:
  exec:
    sso.groups: [Executives]
    config.default_role: true
""")

    with pytest.raises(
        ValueError, match="Only one ACL entry may set config.default_role"
    ):
        acl.parse_acl_config(config_path)

    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
roles: {}
""")

    with pytest.raises(
        ValueError, match="sso.<claim> selectors must set config.default_role"
    ):
        acl.parse_acl_config(config_path)

    with pytest.raises(
        ValueError, match="sso.<claim> selectors must set config.default_role"
    ):
        acl.build_sso_config(
            acl.AclConfig(
                policies=[acl.AclPolicy(name="public", sso={"groups": ["Everyone"]})],
                roles={},
            )
        )


def test_parse_acl_config_rejects_broken_policy_ladder(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Contractors]
  finance:
    sso.groups: [Executives]
roles: {}
""")

    with pytest.raises(ValueError, match="Policy ladder is not nested"):
        acl.parse_acl_config(config_path)


def test_parse_acl_config_rejects_policy_ladder_with_new_sso_claim(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  internal:
    sso.groups: [Employees]
  exec:
    sso.users: [ernest@quilt.bio]
roles: {}
""")

    with pytest.raises(ValueError, match="Policy ladder is not nested"):
        acl.parse_acl_config(config_path)


def test_parse_acl_config_rejects_reserved_inline_names(tmp_path: Path) -> None:
    suffix_path = tmp_path / "suffix.yml"
    suffix_path.write_text("""
policies:
  exec__inline:
    sso.groups: [Everyone]
roles: {}
""")
    with pytest.raises(ValueError, match="reserved for generated inline-role policies"):
        acl.parse_acl_config(suffix_path)

    collision_path = tmp_path / "collision.yml"
    collision_path.write_text("""
policies:
  exec__inline:
    sso.groups: [Everyone]
roles:
  exec:
    sso.groups: [Executives]
""")
    with pytest.raises(ValueError, match="reserved for generated inline-role policies"):
        acl.parse_acl_config(collision_path)


def test_parse_acl_config_rejects_synthetic_role_name_collision(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
  internal:
    sso.groups: [Employees]
roles:
  internal_public:
    sso.groups: [Executives]
""")

    with pytest.raises(ValueError, match="Synthesized role 'internal_public'"):
        acl.parse_acl_config(config_path)


def test_policy_role_alias_is_normalized_and_propagated(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
  leadership:
    name: "  executives  "
    sso.groups: [Executives]
    config.default_role: true
""")

    config = acl.parse_acl_config(config_path)
    desired = acl._build_desired_acl_state(config)
    sso = yaml.safe_load(acl.build_sso_config(config) or "")

    assert config.policies[1].role_name == "executives"
    assert list(desired.role_updates) == ["public", "executives"]
    assert desired.default_role_name == "executives"
    assert [mapping["roles"] for mapping in sso["mappings"]] == [
        ["public"],
        ["executives"],
    ]


def test_policy_role_alias_rejects_generated_role_collision(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    name: shared
    sso.groups: [Everyone]
  internal:
    name: shared
    sso.groups: [Employees]
""")

    with pytest.raises(ValueError, match="Synthesized role 'shared'.*conflicts"):
        acl.parse_acl_config(config_path)


def test_all_buckets_includes_inline_role_buckets() -> None:
    config = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public", sso={"groups": ["Everyone"]}, read=["bucket-a"]
            )
        ],
        roles={
            "exec": acl.AclStaticRole(
                name="exec",
                sso={"groups": ["Executives"]},
                read=["bucket-b"],
                read_write=["bucket-c"],
            )
        },
    )

    assert acl.all_buckets(config) == {"bucket-a", "bucket-b", "bucket-c"}


def test_build_sso_config_emits_policy_and_static_role_mappings() -> None:
    config = acl.parse_acl_config(Path("stack-acl.example.yaml"))

    sso_config = acl.build_sso_config(config)
    assert sso_config is not None
    payload = yaml.safe_load(sso_config)

    assert payload["default_role"] == "internal_public"
    assert payload["mappings"][0]["roles"] == ["public"]
    assert payload["mappings"][1]["roles"] == ["internal_public"]
    assert payload["mappings"][2]["roles"] == ["exec"]
    assert payload["mappings"][2]["admin"] is True

    # Non-admin mappings must omit `admin` entirely. Under union_roles, the
    # server treats admin as a tri-state vote (None=non-vote, True=grant,
    # False=veto); emitting admin:false here would veto the admin grant from
    # any co-matching admin role.
    assert "admin" not in payload["mappings"][0]
    assert "admin" not in payload["mappings"][1]


def test_build_sso_config_emits_arbitrary_sso_claim_schema(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
  sales:
    sso.department: [Sales]
roles:
  owner:
    sso.email: [owner@example.com]
    config.policies: [public]
""")

    config = acl.parse_acl_config(config_path)
    sso_config = acl.build_sso_config(config)
    assert sso_config is not None
    payload = yaml.safe_load(sso_config)

    assert payload["mappings"][1]["schema"]["properties"] == {
        "department": {
            "anyOf": [
                {"const": "Sales"},
                {"type": "array", "contains": {"const": "Sales"}},
            ]
        }
    }
    assert payload["mappings"][1]["schema"]["required"] == ["department"]
    assert payload["mappings"][2]["schema"]["properties"] == {
        "email": {
            "anyOf": [
                {"const": "owner@example.com"},
                {"type": "array", "contains": {"const": "owner@example.com"}},
            ]
        }
    }
    assert payload["mappings"][2]["schema"]["required"] == ["email"]


def test_user_block_reconciles_primary_extra_roles_and_admin() -> None:
    roles = {
        "Old": acl.AclStaticRole(name="Old"),
        "New": acl.AclStaticRole(name="New"),
        "Extra": acl.AclStaticRole(name="Extra"),
    }
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    current.users.append(
        SimpleNamespace(
            name="alice",
            role=current.managed_roles["Old"],
            extra_roles=[],
            is_admin=False,
        )
    )
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={
            "alice": acl.AclUserConfig(role="New", extra_roles=("Extra",), admin=True)
        },
    )

    diff = acl.compute_diff(desired, current)

    assert diff.users_to_update == [
        acl.AclUserUpdate(
            name="alice",
            role="New",
            extra_roles=("Extra",),
            role_changed=True,
            admin=True,
            admin_changed=True,
        )
    ]


def test_user_role_update_is_skipped_when_sso_clear_fails() -> None:
    role_calls: list[Any] = []
    admin_calls: list[Any] = []
    stack = _fake_stack(
        users=SimpleNamespace(
            set_role=lambda *args, **kwargs: role_calls.append((args, kwargs)),
            set_admin=lambda *args: admin_calls.append(args),
        ),
        sso_config=SimpleNamespace(
            set=lambda _text: (_ for _ in ()).throw(RuntimeError("clear failed"))
        ),
    )
    current = replace(_empty_current_state(), sso_config_text="version: '1.0'")
    diff = acl.AclDiff(
        users_to_update=[
            acl.AclUserUpdate(
                name="alice",
                role="New",
                role_changed=True,
                admin=True,
                admin_changed=True,
            )
        ]
    )

    warnings = acl.apply_acl(stack, diff, current)

    assert role_calls == []
    assert admin_calls == []
    assert any("SSO config could not be cleared" in warning for warning in warnings)
    assert any("role assignment skipped" in warning for warning in warnings)
    assert any("admin elevation skipped" in warning for warning in warnings)


def test_user_admin_elevation_is_skipped_when_role_update_fails() -> None:
    admin_calls: list[Any] = []

    def fail_role(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("role update failed")

    stack = _fake_stack(
        users=SimpleNamespace(
            set_role=fail_role,
            set_admin=lambda *args: admin_calls.append(args),
        )
    )
    diff = acl.AclDiff(
        users_to_update=[
            acl.AclUserUpdate(
                name="alice",
                role="New",
                role_changed=True,
                admin=True,
                admin_changed=True,
            )
        ]
    )

    warnings = acl.apply_acl(stack, diff, _empty_current_state())

    assert admin_calls == []
    assert any("roles could not be updated" in warning for warning in warnings)
    assert any("admin elevation skipped" in warning for warning in warnings)


def test_user_block_skips_unknown_role() -> None:
    current = _empty_current_state()
    current.users.append(
        SimpleNamespace(name="alice", role=None, extra_roles=[], is_admin=False)
    )
    desired = acl.AclConfig(
        policies=[],
        roles={},
        users={"alice": acl.AclUserConfig(role="Missing")},
    )

    diff = acl.compute_diff(desired, current)

    assert diff.users_to_update == []
    assert any("roles: Missing; skipping" in warning for warning in diff.warnings)


def test_non_synthesizing_policy_is_reusable_without_ladder_role(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  SharedPolicy:
    config.synthesize: false
    buckets.read: [shared]
roles:
  Analysts:
    config.policies: [SharedPolicy]
""")

    config = acl.parse_acl_config(config_path)
    desired = acl._build_desired_acl_state(config)

    assert config.policies[0].synthesize is False
    assert list(desired.policy_updates) == ["SharedPolicy"]
    assert list(desired.role_updates) == ["Analysts"]
    assert desired.role_updates["Analysts"].policy_titles == ["SharedPolicy"]
    assert acl.build_sso_config(config) is None


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sso.groups", "[Everyone]", "cannot include sso"),
        ("config.is_admin", "true", "config.is_admin is not valid"),
        ("name", "CustomRole", "name is not valid"),
    ],
)
def test_non_synthesizing_policy_rejects_role_only_fields(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text(f"""
policies:
  SharedPolicy:
    config.synthesize: false
    {field}: {value}
roles: {{}}
""")

    with pytest.raises(ValueError, match=message):
        acl.parse_acl_config(config_path)


def test_reusable_policy_is_excluded_from_mixed_synthesized_ladder() -> None:
    config = acl.AclConfig(
        policies=[
            acl.AclPolicy(name="public", sso={"groups": ["Everyone"]}),
            acl.AclPolicy(name="SharedPolicy", synthesize=False),
        ],
        roles={
            "Analysts": acl.AclStaticRole(name="Analysts", policies=["SharedPolicy"])
        },
    )

    desired = acl._build_desired_acl_state(config)

    assert [role.name for role in desired.synthesized_roles] == ["public"]
    assert desired.role_updates["public"].policy_titles == ["public"]
    assert desired.role_updates["Analysts"].policy_titles == ["SharedPolicy"]


def test_switching_synthesized_policy_to_reusable_deletes_old_role() -> None:
    original = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="SharedPolicy",
                sso={"groups": ["Everyone"]},
                read=["shared"],
                default_role=True,
            )
        ],
        roles={},
    )
    desired = acl.AclConfig(
        policies=[
            acl.AclPolicy(name="SharedPolicy", read=["shared"], synthesize=False)
        ],
        roles={},
    )

    diff = acl.compute_diff(desired, _current_state_for_config(original))

    assert diff.roles_to_delete == ["SharedPolicy"]
    assert diff.policies_to_delete == []
    assert diff.roles_to_create == []


def test_static_role_without_sso_manages_role_without_sso_update(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
roles:
  password-users:
    config.policies: [public]
    buckets.read: [private]
""")

    config = acl.parse_acl_config(config_path)
    desired = acl._build_desired_acl_state(config)

    assert config.roles["password-users"].sso == {}
    assert desired.role_updates["password-users"].policy_titles == [
        "public",
        "password-users__inline",
    ]
    sso_text = acl.build_sso_config(config)
    assert sso_text is not None
    sso = yaml.safe_load(sso_text)
    assert all(mapping["roles"] != ["password-users"] for mapping in sso["mappings"])


def test_static_role_can_be_default_role(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies: {}
roles:
  password-users:
    config.default_role: true
""")

    config = acl.parse_acl_config(config_path)
    diff = acl.compute_diff(config, _empty_current_state())

    assert config.roles["password-users"].default_role is True
    assert acl.build_sso_config(config) is None
    assert diff.default_role_name == "password-users"
    assert diff.default_role_needs_update is True
    acl.print_diff(diff)
    assert "~ default role password-users" in capsys.readouterr().out

    config_with_sso = acl.AclConfig(
        policies=[],
        roles={
            **config.roles,
            "employees": acl.AclStaticRole(
                name="employees", sso={"groups": ["Employees"]}
            ),
        },
    )
    sso_config = acl.build_sso_config(config_with_sso)
    assert sso_config is not None
    assert yaml.safe_load(sso_config)["default_role"] == "password-users"


def test_policy_config_is_admin_marks_synthesized_role_admin(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
    config.is_admin: true
roles: {}
""")

    config = acl.parse_acl_config(config_path)
    sso_config = acl.build_sso_config(config)
    assert sso_config is not None
    payload = yaml.safe_load(sso_config)

    assert config.policies[0].is_admin is True
    assert payload["mappings"][0]["roles"] == ["public"]
    assert payload["mappings"][0]["admin"] is True


def test_policy_config_is_admin_false_vetoes_generated_role_admin_and_warns(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
    config.is_admin: true
  internal:
    sso.groups: [Employees]
    config.is_admin: false
roles: {}
""")

    desired = acl.parse_acl_config(config_path)
    diff = acl.compute_diff(desired, _empty_current_state())
    assert diff.sso_config_text is not None
    payload = yaml.safe_load(diff.sso_config_text)

    assert payload["mappings"][0]["roles"] == ["public"]
    assert payload["mappings"][0]["admin"] is True
    assert payload["mappings"][1]["roles"] == ["internal_public"]
    assert payload["mappings"][1]["admin"] is False
    assert any(
        "config.is_admin: false" in warning
        and "vetoes" in warning
        and "internal_public" in warning
        for warning in diff.warnings
    )


def test_compute_diff_from_simpler_stack_acl_example_against_empty_state() -> None:
    desired = acl.parse_acl_config(Path("stack-acl.example.yaml"))
    current = _empty_current_state()

    diff = acl.compute_diff(desired, current)

    assert diff.buckets_to_add == [
        "quilt-bake",
        "quilt-dev",
        "quilt-example",
        "quilt-leadership",
        "udp-spec",
    ]
    assert [policy.title for policy in diff.policies_to_create] == [
        "public",
        "internal",
        "exec__inline",
    ]
    assert [role.name for role in diff.roles_to_create] == [
        "public",
        "internal_public",
        "exec",
    ]
    assert diff.sso_is_create is True
    assert diff.sso_needs_update is True


def test_compute_diff_two_policy_ladder_synthesizes_expected_roles() -> None:
    desired = acl.parse_acl_config(Path("stack-acl.example.yaml"))
    current = _empty_current_state()

    diff = acl.compute_diff(desired, current)

    synth_creates = [role for role in diff.roles_to_create if role.name != "exec"]
    assert [(role.name, role.policy_titles) for role in synth_creates] == [
        ("public", ["public"]),
        ("internal_public", ["public", "internal"]),
    ]


def test_compute_diff_single_policy_config_produces_one_synthesized_role() -> None:
    desired = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public",
                sso={"groups": ["Everyone"]},
                read=["bucket-a"],
                default_role=True,
            )
        ],
        roles={},
    )

    diff = acl.compute_diff(desired, _empty_current_state())

    assert [role.name for role in diff.roles_to_create] == ["public"]
    assert "default_role: public" in (diff.sso_config_text or "")


def test_reordering_policies_changes_synthesized_role_names() -> None:
    first = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public",
                sso={"groups": ["Everyone"]},
                read=["bucket-a"],
                default_role=True,
            ),
            acl.AclPolicy(
                name="internal", sso={"groups": ["Everyone"]}, read=["bucket-b"]
            ),
        ],
        roles={},
    )
    second = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="internal",
                sso={"groups": ["Everyone"]},
                read=["bucket-b"],
                default_role=True,
            ),
            acl.AclPolicy(
                name="public", sso={"groups": ["Everyone"]}, read=["bucket-a"]
            ),
        ],
        roles={},
    )

    first_names = [
        role.name
        for role in acl.compute_diff(first, _empty_current_state()).roles_to_create
    ]
    second_names = [
        role.name
        for role in acl.compute_diff(second, _empty_current_state()).roles_to_create
    ]

    assert first_names == ["public", "internal_public"]
    assert second_names == ["internal", "public_internal"]


def test_static_role_with_inline_buckets_creates_hidden_inline_policy() -> None:
    desired = acl.parse_acl_config(Path("stack-acl.example.yaml"))

    diff = acl.compute_diff(desired, _empty_current_state())

    exec_role = next(role for role in diff.roles_to_create if role.name == "exec")
    assert exec_role.policy_titles == ["public", "internal", "exec__inline"]
    assert any(policy.title == "exec__inline" for policy in diff.policies_to_create)


def test_compute_diff_is_idempotent_against_matching_current_state() -> None:
    desired = acl.parse_acl_config(Path("stack-acl.example.yaml"))
    current = _current_state_for_config(desired)

    diff = acl.compute_diff(desired, current)

    assert diff.has_changes() is False
    assert diff.warnings == []


def test_compute_diff_preserves_registry_managed_canary_resources() -> None:
    desired = acl.AclConfig(policies=[], roles={})
    current = _empty_current_state()
    current.managed_policies.update(
        {
            "CanaryBucketAccess": FakePolicy(
                id="id-canary-policy",
                title="CanaryBucketAccess",
                managed=True,
                permissions=[],
                roles=[],
            ),
            "other-policy": FakePolicy(
                id="id-other-policy",
                title="other-policy",
                managed=True,
                permissions=[],
                roles=[],
            ),
        }
    )
    current.managed_roles.update(
        {
            "Canary": FakeRole(
                id="id-canary-role",
                name="Canary",
                policies=[],
                permissions=[],
            ),
            "other-role": FakeRole(
                id="id-other-role",
                name="other-role",
                policies=[],
                permissions=[],
            ),
        }
    )

    diff = acl.compute_diff(desired, current)

    assert diff.policies_to_delete == ["other-policy"]
    assert diff.roles_to_delete == ["other-role"]


def test_compute_diff_warns_and_skips_unmanaged_name_collisions() -> None:
    desired = acl.parse_acl_config(Path("stack-acl.example.yaml"))
    current = _empty_current_state()
    current.unmanaged_policies["public"] = FakePolicy(
        id="u-policy",
        title="public",
        managed=False,
        permissions=[],
        roles=[],
    )
    current.unmanaged_roles["exec"] = FakeRole(
        id="u-role",
        name="exec",
        policies=[],
        permissions=[],
        typename__="UnmanagedRole",
    )

    diff = acl.compute_diff(desired, current)

    assert any(
        "Policy 'public' already exists as unmanaged" in warning
        for warning in diff.warnings
    )
    assert any(
        "Role 'exec' already exists as unmanaged" in warning
        for warning in diff.warnings
    )
    assert "public" not in [policy.title for policy in diff.policies_to_create]
    assert "exec" not in [role.name for role in diff.roles_to_create]


def test_policy_drift_skips_unmanaged_name_collision() -> None:
    desired = acl.AclConfig(
        policies=[acl.AclPolicy(name="public", sso={"groups": ["Everyone"]})],
        roles={},
    )
    current = _empty_current_state()
    unmanaged = FakePolicy(
        id="u-policy", title="public", managed=False, permissions=[], roles=[]
    )
    current.unmanaged_policies["public"] = unmanaged
    current.all_policies["public"] = unmanaged

    assert acl.detect_policy_drift(desired, current) == []


def test_apply_acl_refetches_policy_after_failed_create() -> None:
    persisted = FakePolicy(
        id="policy-id", title="public", managed=True, permissions=[], roles=[]
    )
    role_policy_ids: list[list[str]] = []

    def fail_create(_title: str, *, permissions: list[Any]) -> None:
        raise RuntimeError("Internal Server Error")

    stack = _fake_stack(
        policies=SimpleNamespace(
            create_managed=fail_create,
            list=lambda: [persisted],
        ),
        roles=SimpleNamespace(
            create_managed=lambda _name, *, policies: role_policy_ids.append(policies)
        ),
    )
    diff = acl.AclDiff(
        policies_to_create=[acl.PolicyUpdate(title="public", permissions=[])],
        roles_to_create=[acl.RoleUpdate(name="public", policy_titles=["public"])],
    )

    warnings = acl.apply_acl(stack, diff, _empty_current_state())

    assert role_policy_ids == [["policy-id"]]
    assert any("could not be created" in warning for warning in warnings)


def test_reset_policy_missing_on_server_is_directly_reapplied() -> None:
    stack = _fake_stack(
        policies=SimpleNamespace(
            delete=lambda _ref: pytest.fail("missing policy must not be deleted")
        )
    )

    warnings, users = acl.reset_policy(stack, "missing", _empty_current_state())

    assert warnings == []
    assert users == []


def test_changing_policy_groups_updates_sso_config() -> None:
    original = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public",
                sso={"groups": ["Everyone"]},
                read=["bucket-a"],
                default_role=True,
            )
        ],
        roles={},
    )
    updated = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public",
                sso={"groups": ["Employees"]},
                read=["bucket-a"],
                default_role=True,
            )
        ],
        roles={},
    )
    current = _current_state_for_config(original)

    diff = acl.compute_diff(updated, current)

    assert diff.sso_needs_update is True
    assert "Employees" in (diff.sso_config_text or "")


def test_policy_rename_cleans_up_old_synthesized_role_in_single_pass() -> None:
    original = acl.parse_acl_config(Path("stack-acl.example.yaml"))
    current = _current_state_for_config(original)

    renamed = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public",
                sso={"groups": ["Everyone"]},
                read=["quilt-example"],
                default_role=True,
            ),
            acl.AclPolicy(
                name="employees",
                sso={"groups": ["Employees"]},
                read=["quilt-leadership"],
                read_write=["quilt-bake", "quilt-dev"],
            ),
        ],
        roles={
            "exec": acl.AclStaticRole(
                name="exec",
                sso={"groups": ["Executives"]},
                policies=["public", "employees"],
                read_write=["quilt-leadership"],
                is_admin=True,
            )
        },
    )

    diff = acl.compute_diff(renamed, current)

    assert "internal_public" in diff.roles_to_delete
    assert "internal" in diff.policies_to_delete
    assert "employees_public" in [role.name for role in diff.roles_to_create]


def test_print_diff_verbose_shows_synthesized_roles(capsys) -> None:
    desired = acl.parse_acl_config(Path("stack-acl.example.yaml"))
    diff = acl.compute_diff(desired, _empty_current_state())

    acl.print_diff(diff, verbose=True, desired=desired)
    out = capsys.readouterr().out

    assert "role internal_public (synthesized from policies public, internal)" in out
    assert "policy exec__inline (generated inline policy)" in out
    assert "admin: true" in out


def test_print_current_state_summarizes_server_acl(capsys) -> None:
    current = _current_state_for_config(
        acl.parse_acl_config(Path("stack-acl.example.yaml"))
    )
    current.users.append(
        SimpleNamespace(
            name="alice",
            email="alice@example.com",
            role=current.managed_roles["exec"],
            extra_roles=[current.managed_roles["internal_public"]],
            is_admin=True,
            is_active=True,
            is_sso_only=False,
            is_service=False,
            date_joined=datetime(2026, 8, 1, tzinfo=timezone.utc),
            last_login=None,
        )
    )

    acl.print_current_state(current)
    out = capsys.readouterr().out

    assert "policy public (managed)" in out
    assert "role internal_public (default) (managed)" in out
    assert "user alice" in out
    assert "active role: exec" in out
    assert "extra roles: internal_public" in out
    assert "date joined: 2026-08-01T00:00:00+00:00" in out
    assert "last login: (none)" in out
    assert "default_role: internal_public" in out
    assert "groups=Executives -> [exec] (admin)" in out


def test_apply_acl_orders_operations_and_updates_sso_before_role_deletes(
    monkeypatch,
) -> None:
    calls: list[tuple[Any, ...]] = []

    def bucket_add(name: str, title: str) -> FakeBucket:
        calls.append(("bucket_add", name, title))
        return FakeBucket(name=name, title=title)

    def policy_create(title: str, *, permissions: list[Any]) -> FakePolicy:
        calls.append(("policy_create", title))
        return FakePolicy(
            id=f"id-{title}",
            title=title,
            managed=True,
            permissions=permissions,
            roles=[],
        )

    created_roles: list[FakeRole] = []

    def role_create(name: str, policies: list[str]) -> FakeRole:
        calls.append(("role_create", name, list(policies)))
        role = FakeRole(id=f"id-{name}", name=name, policies=[], permissions=[])
        created_roles.append(role)
        return role

    def sso_set(text: str) -> SimpleNamespace:
        calls.append(("sso_set", yaml.safe_load(text)["default_role"]))
        return SimpleNamespace(text=text)

    stack = _fake_stack(
        buckets=SimpleNamespace(add=bucket_add),
        policies=SimpleNamespace(
            create_managed=policy_create,
            update_managed=lambda *args, **kwargs: None,
            delete=lambda title: calls.append(("policy_delete", title)),
        ),
        roles=SimpleNamespace(
            create_managed=role_create,
            update_managed=lambda *args, **kwargs: None,
            list=lambda: [*created_roles],
            set_default=lambda ref: calls.append(("default_role", ref)),
            delete=lambda name: calls.append(("role_delete", name)),
        ),
        sso_config=SimpleNamespace(set=sso_set),
    )

    diff = acl.AclDiff(
        buckets_to_add=["bucket-a"],
        policies_to_create=[
            acl.PolicyUpdate(
                title="public", permissions=[acl.Permission.read("bucket-a")]
            )
        ],
        roles_to_create=[acl.RoleUpdate(name="public", policy_titles=["public"])],
        default_role_name="public",
        default_role_needs_update=True,
        roles_to_delete=["legacy_role"],
        policies_to_delete=["legacy_policy"],
        sso_config_text=acl.build_sso_config(
            acl.AclConfig(
                policies=[
                    acl.AclPolicy(
                        name="public",
                        sso={"groups": ["Everyone"]},
                        read=["bucket-a"],
                        default_role=True,
                    )
                ],
                roles={},
            )
        ),
        sso_needs_update=True,
    )
    current = _empty_current_state()
    legacy_policy = FakePolicy(
        id="id-legacy-policy",
        title="legacy_policy",
        managed=True,
        permissions=[],
        roles=[],
    )
    current.managed_policies[legacy_policy.title] = legacy_policy
    current.all_policies[legacy_policy.title] = legacy_policy

    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda stack, bucket, *, title=None: stack.admin.buckets.add(
            name=bucket, title=title or bucket
        ),
    )
    acl.apply_acl(stack, diff, current, no_preflight=True)

    assert calls == [
        ("bucket_add", "bucket-a", "bucket-a"),
        ("policy_create", "public"),
        ("role_create", "public", ["id-public"]),
        ("default_role", "id-public"),
        ("sso_set", "public"),
        ("role_delete", "legacy_role"),
        ("policy_delete", "id-legacy-policy"),
    ]


def test_apply_acl_detaches_users_before_deleting_roles() -> None:
    calls: list[tuple[Any, ...]] = []

    def sso_set(text: str | None) -> None:
        calls.append(("sso_set", text))

    stack = _fake_stack(
        policies=SimpleNamespace(delete=lambda title: None),
        roles=SimpleNamespace(
            delete=lambda name: calls.append(("role_delete", name)),
            get_default=lambda: SimpleNamespace(name="default"),
        ),
        sso_config=SimpleNamespace(set=sso_set),
        users=SimpleNamespace(
            list=lambda: [
                SimpleNamespace(
                    name="alice",
                    role=SimpleNamespace(name="legacy_role"),
                    extra_roles=[],
                )
            ],
            remove_roles=lambda name, roles, *, fallback: calls.append(
                ("remove_roles", name, list(roles), fallback)
            ),
        ),
    )

    diff = acl.AclDiff(
        roles_to_delete=["legacy_role"],
    )
    current = replace(
        _empty_current_state(), sso_config_text="version: '1.0'\nmappings: []\n"
    )

    warnings = acl.apply_acl(stack, diff, current)

    assert warnings == []
    assert calls == [
        ("sso_set", None),
        ("remove_roles", "alice", ["legacy_role"], "default"),
        ("role_delete", "legacy_role"),
        ("sso_set", "version: '1.0'\nmappings: []\n"),
    ]


def test_apply_acl_restores_pruned_sso_after_role_delete_clear() -> None:
    sso_calls: list[dict[str, Any] | None] = []

    def role_create(name: str, policies: list[str]) -> FakeRole:
        if name == "exec":
            raise RuntimeError("role create failed")
        return FakeRole(id=f"id-{name}", name=name, policies=[], permissions=[])

    def sso_set(text: str | None) -> None:
        sso_calls.append(None if text is None else yaml.safe_load(text))

    stack = _fake_stack(
        roles=SimpleNamespace(
            create_managed=role_create,
            delete=lambda name: None,
            get_default=lambda: SimpleNamespace(name="public"),
        ),
        sso_config=SimpleNamespace(set=sso_set),
        users=SimpleNamespace(
            list=lambda: [
                SimpleNamespace(
                    name="alice",
                    role=SimpleNamespace(name="legacy_role"),
                    extra_roles=[],
                )
            ],
            remove_roles=lambda *args, **kwargs: None,
        ),
    )

    diff = acl.AclDiff(
        roles_to_create=[
            acl.RoleUpdate(name="public", policy_titles=[]),
            acl.RoleUpdate(name="exec", policy_titles=[]),
        ],
        roles_to_delete=["legacy_role"],
        sso_config_text=yaml.safe_dump(
            {
                "version": "1.0",
                "default_role": "public",
                "mappings": [
                    {
                        "schema": {"properties": {}, "required": []},
                        "roles": ["public"],
                    },
                    {
                        "schema": {"properties": {}, "required": []},
                        "roles": ["exec"],
                    },
                ],
            }
        ),
        sso_needs_update=True,
    )

    warnings = acl.apply_acl(stack, diff, _empty_current_state())

    assert any("Role 'exec' could not be created" in warning for warning in warnings)
    assert [call["default_role"] if call else None for call in sso_calls] == [
        "public",
        None,
        "public",
    ]
    restored_payload = sso_calls[0]
    assert restored_payload is not None
    assert restored_payload == sso_calls[2]
    assert restored_payload["mappings"] == [
        {"schema": {"properties": {}, "required": []}, "roles": ["public"]}
    ]


def test_apply_acl_detaches_policies_before_deleting_roles() -> None:
    calls: list[tuple[Any, ...]] = []
    inline_policy = FakePolicy(
        id="id-inline",
        title="exec__inline",
        managed=True,
        permissions=[],
        roles=[],
    )
    current = _empty_current_state()
    current.managed_policies["exec__inline"] = inline_policy
    current.all_policies.update(current.managed_policies)
    current.managed_roles["exec"] = FakeRole(
        id="id-exec",
        name="exec",
        policies=[FakePolicySummary(id="id-inline", title="exec__inline")],
        permissions=[],
    )
    current.all_roles.update(current.managed_roles)

    def role_update(role_ref: str, *, name: str, policies: list[str]) -> None:
        calls.append(("role_update", role_ref, name, list(policies)))

    stack = _fake_stack(
        roles=SimpleNamespace(
            update_managed=role_update,
            delete=lambda name: calls.append(("role_delete", name)),
        ),
        users=SimpleNamespace(list=lambda: []),
        sso_config=SimpleNamespace(get=lambda: None),
        policies=SimpleNamespace(delete=lambda title: None),
    )

    warnings = acl.apply_acl(stack, acl.AclDiff(roles_to_delete=["exec"]), current)

    assert warnings == []
    assert calls == [
        ("role_update", "id-exec", "exec", []),
        ("role_delete", "id-exec"),
    ]


def test_apply_acl_falls_back_to_policy_update_when_role_detach_fails(
    capsys,
) -> None:
    calls: list[tuple[Any, ...]] = []
    exec_role = FakeRole(
        id="id-exec",
        name="exec",
        policies=[FakePolicySummary(id="id-inline", title="exec__inline")],
        permissions=[],
    )
    inline_policy = FakePolicy(
        id="id-inline",
        title="exec__inline",
        managed=True,
        permissions=[],
        roles=[exec_role],
    )
    current = _empty_current_state()
    current.managed_roles["exec"] = exec_role
    current.all_roles.update(current.managed_roles)
    current.managed_policies["exec__inline"] = inline_policy
    current.all_policies.update(current.managed_policies)

    def role_update(role_ref: str, *, name: str, policies: list[str]) -> None:
        calls.append(("role_update", role_ref, name, list(policies)))
        raise RuntimeError("role update failed")

    def policy_update(
        policy_ref: str,
        *,
        title: str,
        permissions: list[Any],
        roles: list[str],
    ) -> FakePolicy:
        calls.append(("policy_update", policy_ref, title, list(roles)))
        return inline_policy

    stack = _fake_stack(
        roles=SimpleNamespace(
            update_managed=role_update,
            delete=lambda name: calls.append(("role_delete", name)),
        ),
        policies=SimpleNamespace(
            update_managed=policy_update,
            delete=lambda title: None,
        ),
        users=SimpleNamespace(list=lambda: []),
        sso_config=SimpleNamespace(get=lambda: None),
    )

    warnings = acl.apply_acl(stack, acl.AclDiff(roles_to_delete=["exec"]), current)

    assert warnings == []
    assert "role exec: role update failed" not in capsys.readouterr().err
    assert calls == [
        ("role_update", "id-exec", "exec", []),
        ("policy_update", "id-inline", "exec__inline", []),
        ("role_delete", "id-exec"),
    ]


def test_apply_acl_detaches_deleted_policies_from_surviving_roles() -> None:
    calls: list[tuple[Any, ...]] = []
    legacy_policy = FakePolicy(
        id="id-legacy",
        title="legacy_policy",
        managed=True,
        permissions=[],
        roles=[],
    )
    keep_policy = FakePolicy(
        id="id-keep",
        title="keep_policy",
        managed=True,
        permissions=[],
        roles=[],
    )
    current = _empty_current_state()
    current.managed_policies.update(
        {"legacy_policy": legacy_policy, "keep_policy": keep_policy}
    )
    current.all_policies.update(current.managed_policies)
    current.managed_roles["survivor"] = FakeRole(
        id="id-survivor",
        name="survivor",
        policies=[
            FakePolicySummary(id="id-legacy", title="legacy_policy"),
            FakePolicySummary(id="id-keep", title="keep_policy"),
        ],
        permissions=[],
    )
    current.all_roles.update(current.managed_roles)

    def role_update(role_ref: str, *, name: str, policies: list[str]) -> None:
        calls.append(("role_update", role_ref, name, list(policies)))

    stack = _fake_stack(
        policies=SimpleNamespace(
            delete=lambda title: calls.append(("policy_delete", title))
        ),
        roles=SimpleNamespace(update_managed=role_update),
    )

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(policies_to_delete=["legacy_policy"]),
        current,
    )

    assert warnings == []
    assert calls == [
        ("role_update", "id-survivor", "survivor", ["id-keep"]),
        ("policy_delete", "id-legacy"),
    ]


@pytest.mark.parametrize(
    "payload",
    [{"region": "us-east-1"}, {"account_id": ""}],
    ids=["missing-account-id", "empty-account-id"],
)
def test_apply_acl_requires_control_account_metadata_for_preflight(
    monkeypatch, payload
) -> None:
    direct_adds: list[str] = []
    stack = _fake_stack(
        payload=payload,
        buckets=SimpleNamespace(
            add=lambda **kwargs: direct_adds.append(kwargs["name"])
        ),
    )
    monkeypatch.setattr(
        acl,
        "_register_bucket_with_retry",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("registration must not run without control-account metadata")
        ),
    )

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(buckets_to_add=["bucket-a"]),
        _empty_current_state(),
    )

    assert direct_adds == []
    assert len(warnings) == 1
    assert "control account metadata is required" in warnings[0]
    assert "--no-preflight" in warnings[0]


def test_register_bucket_with_retry_uses_shared_preparation(monkeypatch) -> None:
    from quiltx import bucket as bucket_lib

    s3_client = object()
    sns_client = object()
    sqs_client = object()
    lambda_client = object()
    plan = SimpleNamespace(
        sns_topic_arn="arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications",
        principals_before=(),
        principals_removed=(),
    )
    calls: list[tuple[Any, ...]] = []

    class Session:
        def client(self, service: str, region_name: str | None = None):
            if service == "sns":
                assert region_name == "us-west-2"
                return sns_client
            if service == "sqs":
                assert region_name == "us-west-2"
                return sqs_client
            if service == "lambda":
                assert region_name == "us-west-2"
                return lambda_client
            if service == "sts":
                return SimpleNamespace(
                    get_caller_identity=lambda: {"Account": "111122223333"}
                )
            raise AssertionError(f"unexpected service {service}")

    def build_plan(*args, **kwargs):
        calls.append(
            (
                "plan",
                args,
                kwargs["control_account_id"],
                kwargs["s3_client"],
                kwargs["sns_client"],
                kwargs["sqs_client"],
                kwargs["lambda_client"],
            )
        )
        return plan

    monkeypatch.setattr(
        bucket_lib,
        "resolve_bucket_session",
        lambda *args, **kwargs: (Session(), s3_client, "us-west-2", "prod"),
    )
    monkeypatch.setattr(bucket_lib, "build_bucket_preparation_plan", build_plan)
    monkeypatch.setattr(
        bucket_lib,
        "apply_bucket_preparation",
        lambda candidate, **kwargs: calls.append(
            (
                "apply",
                candidate,
                kwargs["s3_client"],
                kwargs["sns_client"],
                kwargs["sqs_client"],
                kwargs["lambda_client"],
            )
        ),
    )
    stack = _fake_stack(
        buckets=SimpleNamespace(add=lambda **kwargs: calls.append(("add", kwargs)))
    )

    acl._register_bucket_with_retry(stack, "bucket-a", "123456789012", assume_yes=True)

    assert calls == [
        (
            "plan",
            ("bucket-a", "us-west-2", "111122223333"),
            "123456789012",
            s3_client,
            sns_client,
            sqs_client,
            lambda_client,
        ),
        ("apply", plan, s3_client, sns_client, sqs_client, lambda_client),
        (
            "add",
            {
                "name": "bucket-a",
                "title": "bucket-a",
                "sns_notification_arn": plan.sns_topic_arn,
            },
        ),
    ]


def test_apply_acl_uses_cross_account_registration_when_stack_available(
    monkeypatch,
) -> None:
    """When a control account is available, apply_acl goes through the full
    cross-account bucket registration path (including profile retry)."""
    calls: list[tuple[Any, ...]] = []

    def fake_register(
        stack: Any, bucket: str, control_account_id: str, *, assume_yes: bool
    ) -> None:
        calls.append(("register", bucket, control_account_id, assume_yes))

    monkeypatch.setattr(acl, "_register_bucket_with_retry", fake_register)
    stack = _fake_stack(
        payload={"account_id": "111"},
        buckets=SimpleNamespace(add=lambda *a, **kw: None),
    )

    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    acl.apply_acl(stack, diff, _empty_current_state(), assume_yes=True)

    assert calls == [("register", "bucket-a", "111", True)]


def test_apply_acl_no_preflight_uses_graphql_only(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def fake_add_without_preflight(
        stack: Any, bucket: str, *, title: str | None = None
    ):
        calls.append((bucket, title or ""))

    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight", fake_add_without_preflight
    )
    stack = _fake_stack(payload={"account_id": "111"})

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(buckets_to_add=["bucket-a", "bucket-b"]),
        _empty_current_state(),
        no_preflight=True,
    )

    assert warnings == []
    assert calls == [("bucket-a", "bucket-a"), ("bucket-b", "bucket-b")]


def test_apply_acl_no_preflight_failure_does_not_rollback(monkeypatch) -> None:
    calls: list[str] = []

    def fake_add_without_preflight(
        stack: Any, bucket: str, *, title: str | None = None
    ):
        calls.append(bucket)
        if bucket == "bad-bucket":
            raise RuntimeError("BucketDoesNotExist")

    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight", fake_add_without_preflight
    )
    stack = _fake_stack(payload={"account_id": "111"})

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(buckets_to_add=["good-bucket", "bad-bucket"]),
        _empty_current_state(),
        no_preflight=True,
    )

    assert calls == ["good-bucket", "bad-bucket"]
    assert warnings == ["Bucket 'bad-bucket' was not registered: BucketDoesNotExist"]


def test_acl_tool_dry_run_does_not_apply(monkeypatch, capsys) -> None:
    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    current = _empty_current_state()
    _install_acl_tool_stack(monkeypatch)

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "parse_acl_config",
        lambda path: acl.AclConfig(policies=[], roles={}),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(acl_tool.acl_lib, "compute_diff", lambda desired, state: diff)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "apply_acl",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("apply_acl should not be called")
        ),
    )

    result = acl_tool.main(["config.yml", "--dry-run"])

    assert result == 0
    assert "+ bucket bucket-a" in capsys.readouterr().out


def test_acl_tool_yes_flag_applies_without_prompt(monkeypatch) -> None:
    current = _empty_current_state()
    applied: list[str] = []
    _install_acl_tool_stack(monkeypatch)

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "parse_acl_config",
        lambda path: acl.AclConfig(policies=[], roles={}),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "compute_diff",
        lambda desired, state: acl.AclDiff(buckets_to_add=["bucket-a"]),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "print_diff", lambda *args, **kwargs: None)

    def _apply_acl(*_args: Any, **_kwargs: Any) -> list[str]:
        applied.append("applied")
        # A successful apply leaves the bucket registered; the CLI re-reads the
        # server afterwards and reports buckets that are still missing.
        current.buckets["bucket-a"] = FakeBucket(name="bucket-a", title="bucket-a")
        return []

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "apply_acl",
        _apply_acl,
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: (_ for _ in ()).throw(
            AssertionError("input should not be called")
        ),
    )

    result = acl_tool.main(["config.yml", "--yes"])

    assert result == 0
    assert applied == ["applied"]


def test_acl_tool_no_preflight_threads_to_apply(monkeypatch) -> None:
    current = _empty_current_state()
    no_preflight_values: list[bool] = []
    _install_acl_tool_stack(monkeypatch)

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "parse_acl_config",
        lambda path: acl.AclConfig(policies=[], roles={}),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "compute_diff",
        lambda desired, state: acl.AclDiff(buckets_to_add=["bucket-a"]),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "print_diff", lambda *args, **kwargs: None)

    def _apply_acl(*_args: Any, **kwargs: Any) -> list[str]:
        no_preflight_values.append(kwargs["no_preflight"])
        current.buckets["bucket-a"] = FakeBucket(name="bucket-a", title="bucket-a")
        return []

    monkeypatch.setattr(acl_tool.acl_lib, "apply_acl", _apply_acl)

    result = acl_tool.main(["config.yml", "--yes", "--no-preflight"])

    assert result == 0
    assert no_preflight_values == [True]


def test_policy_drift_reapply_preserves_no_preflight(monkeypatch) -> None:
    desired = acl.AclConfig(policies=[], roles={})
    current = _empty_current_state()
    post_reset = _empty_current_state()
    new_diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    no_preflight_values: list[bool] = []
    stack = _fake_stack(users=SimpleNamespace(list=lambda: []))

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "reset_policy",
        lambda *args, **kwargs: ([], []),
    )
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "fetch_current_state",
        lambda _stack: post_reset,
    )
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "compute_diff",
        lambda _desired, _current: new_diff,
    )
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "detect_policy_drift",
        lambda _desired, _current: [],
    )

    def _apply_acl(*_args: Any, **kwargs: Any) -> list[str]:
        no_preflight_values.append(kwargs["no_preflight"])
        return []

    monkeypatch.setattr(acl_tool.acl_lib, "apply_acl", _apply_acl)

    warnings, _ = acl_tool._handle_policy_drift(
        stack,
        [acl.PolicyDrift(title="public", desired=[], actual=[])],
        desired,
        current,
        auto=True,
        verbose=False,
        no_preflight=True,
    )

    assert warnings == []
    assert no_preflight_values == [True]


def test_acl_tool_no_config_shows_current_state(monkeypatch, capsys) -> None:
    current = _empty_current_state()
    current.buckets["bucket-a"] = FakeBucket(name="bucket-a", title="bucket-a")
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)

    result = acl_tool.main([])

    assert result == 0
    assert "bucket bucket-a" in capsys.readouterr().out


def test_acl_tool_json_exports_valid_json_without_header(monkeypatch, capsys) -> None:
    current = replace(_empty_current_state(), default_role_name="readers")
    current.buckets["orphan-bucket"] = FakeBucket(
        name="orphan-bucket", title="Orphan bucket"
    )
    role = FakeRole(id="role-1", name="readers", policies=[], permissions=[])
    current.managed_roles[role.name] = role
    current.all_roles[role.name] = role
    current.users.append(
        SimpleNamespace(
            name="alice",
            email="alice@example.com",
            role=role,
            extra_roles=[],
            is_admin=False,
            is_active=True,
            is_sso_only=False,
            is_service=False,
            date_joined=datetime(2026, 8, 1, tzinfo=timezone.utc),
            last_login=None,
        )
    )
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(
        acl_tool.stack_lib, "current_stack_header", lambda _stack: "HUMAN HEADER"
    )

    result = acl_tool.main(["--json"])
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["catalog"] == "catalog"
    assert payload["default_role"] == "readers"
    assert payload["buckets"] == [{"name": "orphan-bucket", "title": "Orphan bucket"}]
    assert payload["users"] == [
        {
            "name": "alice",
            "email": "alice@example.com",
            "role": "readers",
            "extra_roles": [],
            "is_admin": False,
            "is_active": True,
            "is_sso_only": False,
            "is_service": False,
            "date_joined": "2026-08-01T00:00:00+00:00",
            "last_login": None,
        }
    ]


def test_acl_tool_json_rejects_config_file(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        acl_tool.main(["--json", "config.yml"])

    assert exc_info.value.code == 2
    assert "--json is only valid when config_file is omitted" in capsys.readouterr().err


def test_current_state_yaml_round_trips_static_roles_shared_policies_and_users(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.yml"
    source.write_text("""
policies:
  SharedPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [SharedPolicy]
    buckets.read_write: [bucket-b]
    config.default_role: true
  Observers: {}
users:
  alice:
    role: Analysts
    extra_roles: [Observers]
    admin: true
""")
    current = _current_state_for_config(acl.parse_acl_config(source))
    current.users.append(
        SimpleNamespace(
            name="alice",
            role=current.managed_roles["Analysts"],
            extra_roles=[current.managed_roles["Observers"]],
            is_admin=True,
        )
    )

    exported = acl.current_state_as_acl_yaml(
        current, catalog="example.quiltdata.com", captured_on="2026-08-10"
    )
    exported_path = tmp_path / "exported.yml"
    exported_path.write_text(exported)
    parsed = acl.parse_acl_config(exported_path)
    diff = acl.compute_diff(parsed, current)
    payload = yaml.safe_load(exported)

    assert exported.startswith(
        "# quiltx ACL capture for example.quiltdata.com\n# captured: 2026-08-10\n"
    )
    assert payload["policies"] == {
        "SharedPolicy": {
            "config.synthesize": False,
            "buckets.read": ["bucket-a"],
        }
    }
    assert payload["roles"]["Analysts"] == {
        "buckets.read_write": ["bucket-b"],
        "config.policies": ["SharedPolicy"],
        "config.default_role": True,
    }
    assert payload["users"]["alice"] == {
        "role": "Analysts",
        "extra_roles": ["Observers"],
        "admin": True,
    }
    assert not diff.has_changes()
    assert diff.warnings == []
    assert diff.notices == []


def test_current_state_yaml_can_omit_only_default_role_users(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text("""
policies: {}
roles:
  Default:
    config.default_role: true
  Other: {}
users: {}
""")
    current = _current_state_for_config(acl.parse_acl_config(source))
    default_role = current.managed_roles["Default"]
    other_role = current.managed_roles["Other"]
    current.users.extend(
        [
            SimpleNamespace(
                name="default-only",
                role=default_role,
                extra_roles=[],
                is_admin=False,
            ),
            SimpleNamespace(
                name="default-admin",
                role=default_role,
                extra_roles=[],
                is_admin=True,
            ),
            SimpleNamespace(
                name="default-extra",
                role=default_role,
                extra_roles=[other_role],
                is_admin=False,
            ),
            SimpleNamespace(
                name="other-only",
                role=other_role,
                extra_roles=[],
                is_admin=False,
            ),
        ]
    )

    full = yaml.safe_load(
        acl.current_state_as_acl_yaml(
            current, catalog="catalog", captured_on="2026-08-12"
        )
    )
    concise = yaml.safe_load(
        acl.current_state_as_acl_yaml(
            current,
            catalog="catalog",
            captured_on="2026-08-12",
            omit_default_users=True,
        )
    )

    assert set(full["users"]) == {
        "default-only",
        "default-admin",
        "default-extra",
        "other-only",
    }
    assert concise["users"] == {
        "default-admin": {"role": "Default", "admin": True},
        "default-extra": {
            "role": "Default",
            "extra_roles": ["Other"],
            "admin": False,
        },
        "other-only": {"role": "Other", "admin": False},
    }


def test_current_state_yaml_round_trips_representable_sso(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text("""
policies:
  SharedPolicy:
    config.synthesize: false
roles:
  Owners:
    sso.email: [owner@example.com]
    config.policies: [SharedPolicy]
    config.default_role: true
    config.is_admin: true
users: {}
""")
    current = _current_state_for_config(acl.parse_acl_config(source))
    exported_path = tmp_path / "exported.yml"
    exported_path.write_text(
        acl.current_state_as_acl_yaml(
            current, catalog="catalog", captured_on="2026-08-10"
        )
    )

    parsed = acl.parse_acl_config(exported_path)
    diff = acl.compute_diff(parsed, current)

    assert parsed.roles["Owners"].sso == {"email": ["owner@example.com"]}
    assert parsed.roles["Owners"].default_role is True
    assert parsed.roles["Owners"].is_admin is True
    assert not diff.has_changes()


def test_acl_tool_yaml_exports_valid_config_without_header(monkeypatch, capsys) -> None:
    current = _empty_current_state()
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(
        acl_tool.stack_lib, "current_stack_header", lambda _stack: "HUMAN HEADER"
    )

    result = acl_tool.main(["--yaml"])
    output = capsys.readouterr().out
    payload = yaml.safe_load(output)

    assert result == 0
    assert "HUMAN HEADER" not in output
    assert payload == {"policies": {}, "roles": {}, "users": {}}


def test_acl_tool_yaml_rejects_config_file(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        acl_tool.main(["--yaml", "config.yml"])

    assert exc_info.value.code == 2
    assert "--yaml is only valid when config_file is omitted" in capsys.readouterr().err


def test_acl_tool_omit_default_users_requires_yaml(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        acl_tool.main(["--omit-default-users"])

    assert exc_info.value.code == 2
    assert "--omit-default-users requires --yaml" in capsys.readouterr().err


def test_acl_tool_omit_default_users_rejects_config_file(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        acl_tool.main(["--yaml", "--omit-default-users", "config.yml"])

    assert exc_info.value.code == 2
    assert "--yaml is only valid when config_file is omitted" in capsys.readouterr().err


def test_acl_tool_json_and_yaml_are_mutually_exclusive(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        acl_tool.main(["--json", "--yaml"])

    assert exc_info.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_acl_tool_missing_file_reports_error(capsys) -> None:
    result = acl_tool.main(["/tmp/does-not-exist.yml"])

    assert result == 1
    assert "Error:" in capsys.readouterr().err


def _empty_current_state() -> acl.CurrentState:
    return acl.CurrentState(
        buckets={},
        managed_policies={},
        unmanaged_policies={},
        all_policies={},
        managed_roles={},
        unmanaged_roles={},
        all_roles={},
        sso_config_text=None,
        default_role_name=None,
    )


def _current_state_for_config(config: acl.AclConfig) -> acl.CurrentState:
    desired_state = acl._build_desired_acl_state(config)

    managed_policies = {
        title: FakePolicy(
            id=f"id-{title}",
            title=title,
            managed=True,
            permissions=update.permissions,
            roles=[],
        )
        for title, update in desired_state.policy_updates.items()
    }
    managed_roles = {
        name: FakeRole(
            id=f"id-{name}",
            name=name,
            policies=[
                FakePolicySummary(id=f"id-{title}", title=title)
                for title in update.policy_titles
            ],
            permissions=[],
        )
        for name, update in desired_state.role_updates.items()
    }
    for role in managed_roles.values():
        for policy_summary in role.policies or []:
            policy = managed_policies.get(policy_summary.title)
            if policy is not None:
                policy.roles.append(role)
    unmanaged_roles = {
        name: FakeRole(
            id=f"u-{name}",
            name=name,
            policies=None,
            permissions=[],
            typename__="UnmanagedRole",
        )
        for name, role in config.roles.items()
        if role.unmanaged
    }
    buckets = {
        bucket: FakeBucket(name=bucket, title=bucket)
        for bucket in acl.all_buckets(config)
    }
    sso_config_text = acl.build_sso_config(config)

    return acl.CurrentState(
        buckets=buckets,
        managed_policies=managed_policies,
        unmanaged_policies={},
        all_policies=dict(managed_policies),
        managed_roles=managed_roles,
        unmanaged_roles=unmanaged_roles,
        all_roles={**unmanaged_roles, **managed_roles},
        sso_config_text=sso_config_text,
        default_role_name=desired_state.default_role_name,
    )


def test_apply_acl_prunes_sso_config_when_role_create_fails(monkeypatch) -> None:
    """If one role fails to create, SSO still gets the surviving roles applied."""
    sso_calls: list[Any] = []

    def role_create(name: str, policies: list[str]) -> FakeRole:
        if name == "exec":
            raise RuntimeError("Internal Server Error")
        return FakeRole(id=f"id-{name}", name=name, policies=[], permissions=[])

    def sso_set(text: str) -> SimpleNamespace:
        sso_calls.append(yaml.safe_load(text))
        return SimpleNamespace(text=text)

    stack = _fake_stack(
        buckets=SimpleNamespace(add=lambda *args, **kwargs: None),
        policies=SimpleNamespace(
            create_managed=lambda title, *, permissions: FakePolicy(
                id=f"id-{title}",
                title=title,
                managed=True,
                permissions=permissions,
                roles=[],
            ),
            update_managed=lambda *args, **kwargs: None,
            delete=lambda title: None,
        ),
        roles=SimpleNamespace(
            create_managed=role_create,
            update_managed=lambda *args, **kwargs: None,
            delete=lambda name: None,
        ),
        sso_config=SimpleNamespace(set=sso_set),
    )

    diff = acl.AclDiff(
        policies_to_create=[
            acl.PolicyUpdate(title="public", permissions=[]),
            acl.PolicyUpdate(title="exec", permissions=[]),
        ],
        roles_to_create=[
            acl.RoleUpdate(name="public", policy_titles=["public"]),
            acl.RoleUpdate(name="exec", policy_titles=["exec"]),
        ],
        sso_config_text=yaml.safe_dump(
            {
                "version": "1.0",
                "default_role": "exec",
                "mappings": [
                    {"roles": ["public"], "schema": {}},
                    {"roles": ["exec"], "schema": {}, "admin": True},
                ],
            },
            sort_keys=False,
        ),
        sso_needs_update=True,
    )

    warnings = acl.apply_acl(stack, diff, _empty_current_state())

    # Registry's SsoConfig schema requires default_role; since the configured
    # default_role ("exec") was dropped, we cannot send the payload at all.
    # The SSO update is deferred to a later run.
    assert sso_calls == []
    assert any("default_role" in w for w in warnings)
    assert any("exec" in w for w in warnings)


def test_prune_sso_config_returns_none_when_default_role_dropped() -> None:
    """If default_role's target role is missing, skip SSO entirely.

    The registry's SsoConfig pydantic schema requires default_role; a payload
    without it fails with `config.default_role: field required`. Returning
    None tells the caller to defer the update until the missing role exists.
    """
    config_text = yaml.safe_dump(
        {
            "version": "1.0",
            "union_roles": True,
            "default_role": "internal_public",
            "mappings": [
                {"roles": ["public"], "schema": {}},
                {"roles": ["internal_public"], "schema": {}},
                {"roles": ["exec"], "schema": {}, "admin": True},
            ],
        },
        sort_keys=False,
    )

    pruned, dropped = acl._prune_sso_config_for_missing_roles(
        config_text, available_roles={"public"}
    )

    assert pruned is None
    assert dropped == {"internal_public", "exec"}


def test_prune_sso_config_keeps_payload_when_default_role_survives() -> None:
    """If only mapping-only roles are missing, the SSO update still goes."""
    config_text = yaml.safe_dump(
        {
            "version": "1.0",
            "union_roles": True,
            "default_role": "public",
            "mappings": [
                {"roles": ["public"], "schema": {}},
                {"roles": ["exec"], "schema": {}, "admin": True},
            ],
        },
        sort_keys=False,
    )

    pruned, dropped = acl._prune_sso_config_for_missing_roles(
        config_text, available_roles={"public"}
    )

    assert pruned is not None
    assert dropped == {"exec"}
    payload = yaml.safe_load(pruned)
    assert payload["default_role"] == "public"
    assert payload["mappings"] == [{"roles": ["public"], "schema": {}}]


def test_prune_sso_config_keeps_available_roles_in_multi_role_mapping() -> None:
    """A mapping with both available and missing roles keeps the available ones."""
    config_text = yaml.safe_dump(
        {
            "version": "1.0",
            "mappings": [
                {"roles": ["public", "exec"], "schema": {"x": 1}},
            ],
        },
        sort_keys=False,
    )

    pruned, dropped = acl._prune_sso_config_for_missing_roles(
        config_text, available_roles={"public"}
    )

    assert dropped == {"exec"}
    assert pruned is not None
    payload = yaml.safe_load(pruned)
    # Surviving role keeps its SSO grant; the entry's other metadata is preserved.
    assert payload["mappings"] == [{"roles": ["public"], "schema": {"x": 1}}]


def test_prune_sso_config_returns_none_when_nothing_left_to_apply() -> None:
    config_text = yaml.safe_dump(
        {
            "version": "1.0",
            "default_role": "internal_public",
            "mappings": [{"roles": ["exec"], "schema": {}}],
        },
        sort_keys=False,
    )

    pruned, dropped = acl._prune_sso_config_for_missing_roles(
        config_text, available_roles=set()
    )

    assert pruned is None
    assert dropped == {"internal_public", "exec"}


def test_prune_sso_config_preserves_config_when_all_roles_exist() -> None:
    config_text = yaml.safe_dump(
        {
            "version": "1.0",
            "default_role": "public",
            "mappings": [{"roles": ["public"], "schema": {}}],
        },
        sort_keys=False,
    )

    pruned, dropped = acl._prune_sso_config_for_missing_roles(
        config_text, available_roles={"public"}
    )

    assert dropped == set()
    assert pruned is not None
    assert yaml.safe_load(pruned)["default_role"] == "public"


def test_acl_parser_accepts_catalog_and_api_key_flags() -> None:
    """Story 2 literal: `quiltx catalog acl --catalog X --api-key qk_... apply ...`."""
    parser = acl_tool.build_parser()
    args = parser.parse_args(
        [
            "--catalog",
            "customer-acme",
            "--api-key",
            "qk_test",
            "--no-prompt",
            "config.yaml",
        ]
    )
    assert args.catalog == "customer-acme"
    assert args.api_key == "qk_test"
    assert args.no_prompt is True
    assert args.config_file == "config.yaml"


# Diagnostic helpers (added in 0.13.3 for opaque-500 surfacing).


def test_permissions_for_buckets_dedupes_rw_over_read() -> None:
    """A bucket listed in both read and read_write must yield ONE permission.

    The registry's RolePolicyBucketPermission has a composite PK on
    (role_policy_id, bucket_name); emitting both READ and READ_WRITE for the
    same bucket trips a PK violation that surfaces as an opaque 500 from
    policyCreateManaged. RW implies R, so we drop the redundant READ.
    """
    perms = acl._permissions_for_buckets(
        read=["quilt-dev", "quilt-example"],
        read_write=["quilt-bake", "quilt-dev"],
    )
    rendered = [(p.bucket, p.level.name) for p in perms]
    # quilt-dev appears once, as READ_WRITE.
    assert rendered == [
        ("quilt-example", "READ"),
        ("quilt-bake", "READ_WRITE"),
        ("quilt-dev", "READ_WRITE"),
    ]


def test_permissions_for_buckets_handles_disjoint_inputs() -> None:
    perms = acl._permissions_for_buckets(read=["a"], read_write=["b"])
    rendered = [(p.bucket, p.level.name) for p in perms]
    assert rendered == [("a", "READ"), ("b", "READ_WRITE")]


def test_is_internal_server_error_matches_500_text() -> None:
    assert acl._is_internal_server_error(
        "Internal Server Error: Internal Server Error (path: ['policyCreateManaged'])"
    )
    assert acl._is_internal_server_error("Wrapper: Internal Server Error: foo")


def test_is_internal_server_error_skips_validation_and_auth() -> None:
    assert not acl._is_internal_server_error(
        "errors=[InvalidInputSelectionErrors(path='config.default_role', "
        "message='field required', name='ValidationError')] typename__='InvalidInput'"
    )
    assert not acl._is_internal_server_error("Unauthorized")
    assert not acl._is_internal_server_error("Not Found")
    assert not acl._is_internal_server_error("")


def test_format_exception_avoids_duplicate_graphql_message() -> None:
    exc = RuntimeError("Internal Server Error")
    exc.errors = [SimpleNamespace(message="Internal Server Error", path=["role"])]  # type: ignore[attr-defined]

    assert acl.format_exception(exc) == "Internal Server Error (path: ['role'])"


def test_format_permissions_empty() -> None:
    assert acl._format_permissions([]) == "(none)"


def test_format_permissions_canonicalises_and_renders() -> None:
    perms = [
        Permission(bucket="quilt-bake", level=BucketPermissionLevel.READ_WRITE),
        Permission(bucket="quilt-dev", level=BucketPermissionLevel.READ),
        Permission(bucket="quilt-dev", level=BucketPermissionLevel.READ_WRITE),
    ]
    # Sorted by (bucket, level); enum repr split on '.' to surface just the name.
    assert (
        acl._format_permissions(perms)
        == "READ_WRITE:quilt-bake,READ:quilt-dev,READ_WRITE:quilt-dev"
    )


def test_describe_policy_state_returns_id_arn_and_perms() -> None:
    policy = SimpleNamespace(
        title="internal",
        id="pid-7",
        arn="arn:aws:iam::123:policy/quilt-internal",
        permissions=[
            Permission(bucket="quilt-bake", level=BucketPermissionLevel.READ_WRITE),
        ],
    )
    stack = _fake_stack(
        policies=SimpleNamespace(list=lambda: [policy]),
    )
    out = acl._describe_policy_state(stack, "internal")
    assert out == (
        "server now: id=pid-7, arn=arn:aws:iam::123:policy/quilt-internal, "
        "permissions=[READ_WRITE:quilt-bake]"
    )


def test_describe_policy_state_omits_arn_when_missing() -> None:
    policy = SimpleNamespace(title="internal", id="pid-7", arn=None, permissions=[])
    stack = _fake_stack(policies=SimpleNamespace(list=lambda: [policy]))
    assert acl._describe_policy_state(stack, "internal") == (
        "server now: id=pid-7, permissions=[(none)]"
    )


def test_describe_policy_state_reports_not_present() -> None:
    stack = _fake_stack(policies=SimpleNamespace(list=lambda: []))
    assert (
        acl._describe_policy_state(stack, "internal")
        == "server now: policy not present"
    )


def test_describe_policy_state_reports_refetch_failure() -> None:
    def boom() -> Any:
        raise RuntimeError("graphql down")

    stack = _fake_stack(policies=SimpleNamespace(list=boom))
    out = acl._describe_policy_state(stack, "internal")
    assert out.startswith("refetch failed: ")
    assert "graphql down" in out


def test_acl_tool_dry_run_no_preflight_lists_skipped_steps(monkeypatch, capsys) -> None:
    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    current = _empty_current_state()
    _install_acl_tool_stack(monkeypatch)

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "parse_acl_config",
        lambda path: acl.AclConfig(policies=[], roles={}),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(acl_tool.acl_lib, "compute_diff", lambda desired, state: diff)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "apply_acl",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("apply_acl should not be called")
        ),
    )

    result = acl_tool.main(["config.yml", "--dry-run", "--no-preflight"])

    assert result == 0
    out = capsys.readouterr().out
    assert "--no-preflight" in out
    assert "GraphQL only" in out
    assert "GetBucketPolicy" in out
    assert "SNS topic" in out


def _default_role_diff(name: str = "demo") -> acl.AclDiff:
    return acl.AclDiff(default_role_name=name, default_role_needs_update=True)


def _demo_role() -> FakeRole:
    return FakeRole(
        id="11111111-2222-3333-4444-555555555555",
        name="demo",
        policies=None,
        permissions=[],
    )


def test_apply_acl_sets_default_role_by_id() -> None:
    """set_default must receive the role id: the name falls back to a
    role(id: <name>) lookup that UUID-keyed registries answer with a 500."""
    set_default_calls: list[str] = []
    stack = _fake_stack(
        roles=SimpleNamespace(
            list=lambda: [_demo_role()],
            set_default=lambda ref: set_default_calls.append(ref),
        )
    )

    warnings = acl.apply_acl(stack, _default_role_diff(), _empty_current_state())

    assert warnings == []
    assert set_default_calls == ["11111111-2222-3333-4444-555555555555"]


def test_apply_acl_default_role_sso_conflict_is_ok_when_sso_config_governs(
    capsys,
) -> None:
    """SsoConfigConflict is a no-op when the SSO config names the same default
    (registry locks the settings-level default while SSO governs it)."""

    def conflict(_ref: str) -> None:
        raise quilt3_admin_exceptions.RoleSsoConfigConflictError(None)

    stack = _fake_stack(
        roles=SimpleNamespace(list=lambda: [_demo_role()], set_default=conflict)
    )
    current = replace(
        _empty_current_state(),
        sso_config_text="version: '1.0'\ndefault_role: demo\n",
    )

    warnings = acl.apply_acl(stack, _default_role_diff(), current)

    captured = capsys.readouterr()
    assert warnings == []
    assert "governed by the SSO config" in captured.out
    assert "! default role" not in captured.err


def test_apply_acl_default_role_sso_conflict_warns_on_foreign_sso_config() -> None:
    """A conflict from an SSO config that names a different default is real."""

    def conflict(_ref: str) -> None:
        raise quilt3_admin_exceptions.RoleSsoConfigConflictError(None)

    stack = _fake_stack(
        roles=SimpleNamespace(list=lambda: [_demo_role()], set_default=conflict)
    )
    current = replace(
        _empty_current_state(),
        sso_config_text="version: '1.0'\ndefault_role: other\n",
    )

    warnings = acl.apply_acl(stack, _default_role_diff(), current)

    assert any("could not be updated" in warning for warning in warnings)
    assert any("does not name 'demo'" in warning for warning in warnings)


def test_apply_acl_default_role_conflict_prefers_pending_sso_text(capsys) -> None:
    """When this apply is also writing the SSO config, judge the conflict by
    the pending text, not the stale current one."""

    def conflict(_ref: str) -> None:
        raise quilt3_admin_exceptions.RoleSsoConfigConflictError(None)

    stack = _fake_stack(
        roles=SimpleNamespace(list=lambda: [_demo_role()], set_default=conflict),
        sso_config=SimpleNamespace(set=lambda text: SimpleNamespace(text=text)),
    )
    diff = _default_role_diff()
    diff.sso_config_text = "version: '1.0'\ndefault_role: demo\n"
    diff.sso_needs_update = True
    current = replace(
        _empty_current_state(),
        sso_config_text="version: '1.0'\ndefault_role: other\n",
    )

    warnings = acl.apply_acl(stack, diff, current)

    assert not [w for w in warnings if "Default role" in w]
    assert "governed by the SSO config" in capsys.readouterr().out


def test_apply_acl_default_role_falls_back_to_name_when_unlisted() -> None:
    """A role missing from the fresh list still gets attempted by name."""
    set_default_calls: list[str] = []
    stack = _fake_stack(
        roles=SimpleNamespace(
            list=lambda: [],
            set_default=lambda ref: set_default_calls.append(ref),
        )
    )

    acl.apply_acl(stack, _default_role_diff(), _empty_current_state())

    assert set_default_calls == ["demo"]


# --- built-in unmanaged role mappings (#88) ---------------------------------


def _unmanaged_role(name: str, *, id_: str | None = None) -> FakeRole:
    """A catalog built-in role: IAM-backed, no registry policies."""
    return FakeRole(
        id=id_ or f"u-{name}",
        name=name,
        policies=None,
        permissions=[],
        typename__="UnmanagedRole",
    )


def _with_unmanaged_roles(current: acl.CurrentState, *names: str) -> acl.CurrentState:
    for name in names:
        role = _unmanaged_role(name)
        current.unmanaged_roles[name] = role
        current.all_roles[name] = role
    return current


def test_current_state_yaml_preserves_only_unrepresented_buckets_on_builtins() -> None:
    """Built-in registration references omit buckets captured by managed grants."""
    config = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="shared",
                read=["policy-bucket"],
                synthesize=False,
            )
        ],
        roles={
            "Analysts": acl.AclStaticRole(
                name="Analysts",
                policies=["shared"],
                read_write=["inline-bucket"],
            )
        },
    )
    current = _with_unmanaged_roles(
        _current_state_for_config(config),
        "ReadQuiltBucket",
        "ReadWriteQuiltBucket",
    )
    current.buckets["orphan-bucket"] = FakeBucket(
        name="orphan-bucket", title="Orphan bucket"
    )

    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-08-19"
    )
    payload = yaml.safe_load(exported)

    assert payload["policies"]["shared"]["buckets.read"] == ["policy-bucket"]
    assert payload["roles"]["Analysts"]["buckets.read_write"] == ["inline-bucket"]
    assert payload["roles"]["ReadQuiltBucket"] == {
        "config.unmanaged": True,
        "buckets.read": ["orphan-bucket"],
    }
    assert payload["roles"]["ReadWriteQuiltBucket"] == {
        "config.unmanaged": True,
        "buckets.read_write": ["orphan-bucket"],
    }
    assert "not captured" not in exported


def test_replaying_captured_unmanaged_roles_only_registers_missing_buckets() -> None:
    """Built-in bucket markers register buckets without managing the roles."""
    current = _with_unmanaged_roles(
        _empty_current_state(), "ReadQuiltBucket", "ReadWriteQuiltBucket"
    )
    current.buckets["orphan-bucket"] = FakeBucket(
        name="orphan-bucket", title="Orphan bucket"
    )
    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-08-19"
    )

    parsed = acl.parse_acl_config_text(exported)
    source_diff = acl.compute_diff(parsed, current)
    target = _with_unmanaged_roles(
        _empty_current_state(), "ReadQuiltBucket", "ReadWriteQuiltBucket"
    )
    target_diff = acl.compute_diff(parsed, target)

    assert set(parsed.roles) == {"ReadQuiltBucket", "ReadWriteQuiltBucket"}
    assert all(role.unmanaged for role in parsed.roles.values())
    assert not source_diff.has_changes()
    assert source_diff.warnings == []
    assert target_diff.buckets_to_add == ["orphan-bucket"]
    assert target_diff.roles_to_create == []
    assert target_diff.roles_to_update == []
    assert target_diff.roles_to_delete == []
    assert target_diff.policies_to_create == []
    assert target_diff.policies_to_update == []
    assert target_diff.policies_to_delete == []
    assert target_diff.warnings == []


def test_current_state_yaml_captures_users_and_default_on_unmanaged_role() -> None:
    """A user and the settings default on a built-in role round-trip cleanly."""
    current = replace(
        _with_unmanaged_roles(_empty_current_state(), "ReadQuiltBucket"),
        default_role_name="ReadQuiltBucket",
    )
    current.users.append(
        SimpleNamespace(
            name="alice",
            role=current.unmanaged_roles["ReadQuiltBucket"],
            extra_roles=[],
            is_admin=False,
        )
    )

    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-08-17"
    )
    payload = yaml.safe_load(exported)
    diff = acl.compute_diff(acl.parse_acl_config_text(exported), current)

    assert payload["roles"]["ReadQuiltBucket"] == {
        "config.unmanaged": True,
        "config.default_role": True,
    }
    assert payload["users"]["alice"] == {"role": "ReadQuiltBucket", "admin": False}
    assert not diff.has_changes()
    assert diff.user_downgrades == []
    assert "not captured" not in exported


def test_current_state_yaml_round_trips_sso_mapped_unmanaged_role() -> None:
    """An SSO mapping onto a built-in role no longer leaves SSO uncaptured."""
    current = replace(
        _with_unmanaged_roles(_empty_current_state(), "ReadQuiltBucket"),
        default_role_name="ReadQuiltBucket",
        sso_config_text=yaml.safe_dump(
            {
                "version": "1.0",
                "union_roles": True,
                "default_role": "ReadQuiltBucket",
                "mappings": [
                    {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "groups": {
                                    "type": "array",
                                    "contains": {"const": "Everyone"},
                                }
                            },
                            "required": ["groups"],
                        },
                        "roles": ["ReadQuiltBucket"],
                    }
                ],
            },
            sort_keys=False,
        ),
    )

    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-08-17"
    )
    parsed = acl.parse_acl_config_text(exported)
    diff = acl.compute_diff(parsed, current)

    assert parsed.roles["ReadQuiltBucket"].sso == {"groups": ["Everyone"]}
    assert parsed.roles["ReadQuiltBucket"].unmanaged is True
    assert not diff.sso_needs_update
    assert not diff.has_changes()


def test_parse_acl_config_rejects_grants_on_custom_unmanaged_role(
    tmp_path: Path,
) -> None:
    path = tmp_path / "acl.yml"
    path.write_text("""
policies: {}
roles:
  CustomUnmanaged:
    config.unmanaged: true
    buckets.read: [bucket-a]
""")

    with pytest.raises(ValueError) as error:
        acl.parse_acl_config(path)

    message = str(error.value)
    assert "roles.CustomUnmanaged cannot set buckets.read" in message
    assert "config.unmanaged is true" in message


def test_parse_acl_config_rejects_non_boolean_unmanaged(tmp_path: Path) -> None:
    path = tmp_path / "acl.yml"
    path.write_text("""
policies: {}
roles:
  ReadQuiltBucket:
    config.unmanaged: "yes"
""")

    with pytest.raises(ValueError) as error:
        acl.parse_acl_config(path)

    assert "roles.ReadQuiltBucket.config.unmanaged must be a boolean" in str(
        error.value
    )


def test_compute_diff_warns_when_declared_unmanaged_role_is_absent() -> None:
    desired = acl.AclConfig(
        policies=[],
        roles={
            "ReadQuiltBucket": acl.AclStaticRole(name="ReadQuiltBucket", unmanaged=True)
        },
    )

    diff = acl.compute_diff(desired, _empty_current_state())

    assert any("does not exist on the server" in w for w in diff.warnings)
    assert diff.roles_to_create == []
    assert diff.policies_to_create == []


def test_compute_diff_protects_managed_role_declared_unmanaged() -> None:
    """A name/type mismatch warns instead of deleting a real managed role."""
    current = _empty_current_state()
    managed = FakeRole(id="r1", name="Analysts", policies=[], permissions=[])
    current.managed_roles["Analysts"] = managed
    current.all_roles["Analysts"] = managed
    desired = acl.AclConfig(
        policies=[],
        roles={"Analysts": acl.AclStaticRole(name="Analysts", unmanaged=True)},
    )

    diff = acl.compute_diff(desired, current)

    assert any("exists as a managed role" in w for w in diff.warnings)
    assert diff.roles_to_delete == []
    assert diff.roles_to_update == []


# --- default policies (#105) ------------------------------------------------


_DEFAULT_POLICY_CONFIG = """
policies:
  general:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [open-bucket]
  public:
    sso.groups: [Everyone]
    buckets.read: [quilt-example]
    config.default_role: true
  internal:
    sso.groups: [Employees]
    buckets.read_write: [quilt-dev]
roles:
  exec:
    sso.groups: [Executives]
    config.policies: [public]
    buckets.read_write: [quilt-leadership]
"""


def test_default_policy_composes_last_into_every_managed_role(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text(_DEFAULT_POLICY_CONFIG)

    config = acl.parse_acl_config(config_path)
    desired = acl._build_desired_acl_state(config)

    assert config.policies[0].default_policy is True
    assert desired.role_updates["public"].policy_titles == ["public", "general"]
    assert desired.role_updates["internal_public"].policy_titles == [
        "public",
        "internal",
        "general",
    ]
    assert desired.role_updates["exec"].policy_titles == [
        "public",
        "exec__inline",
        "general",
    ]
    assert [role.policy_titles for role in desired.synthesized_roles] == [
        ["public", "general"],
        ["public", "internal", "general"],
    ]
    assert [role.policy_titles for role in desired.static_roles] == [
        ["public", "exec__inline", "general"]
    ]


def test_default_policy_leaves_synthesized_role_names_unchanged(
    tmp_path: Path,
) -> None:
    flagged_path = tmp_path / "flagged.yml"
    flagged_path.write_text(_DEFAULT_POLICY_CONFIG)
    plain_path = tmp_path / "plain.yml"
    plain_path.write_text(
        _DEFAULT_POLICY_CONFIG.replace("    config.default_policy: true\n", "")
    )

    flagged = acl._build_desired_acl_state(acl.parse_acl_config(flagged_path))
    plain = acl._build_desired_acl_state(acl.parse_acl_config(plain_path))

    assert list(flagged.role_updates) == ["public", "internal_public", "exec"]
    assert list(plain.role_updates) == list(flagged.role_updates)
    assert [role.source_policies for role in flagged.synthesized_roles] == [
        ["public"],
        ["public", "internal"],
    ]


def test_default_policy_is_not_duplicated_when_a_role_lists_it(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  general:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [open-bucket]
  extra:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [extra-bucket]
  public:
    sso.groups: [Everyone]
    config.default_role: true
roles:
  exec:
    sso.groups: [Executives]
    config.policies: [general, public]
""")

    desired = acl._build_desired_acl_state(acl.parse_acl_config(config_path))

    assert desired.role_updates["exec"].policy_titles == ["general", "public", "extra"]
    assert desired.role_updates["public"].policy_titles == [
        "public",
        "general",
        "extra",
    ]


_DEFAULT_POLICY_UNMANAGED_CONFIG = """
policies:
  general:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [open-bucket]
roles:
  Analysts: {}
  ReadQuiltBucket:
    config.unmanaged: true
"""


def test_default_policy_skips_unmanaged_roles_with_a_notice() -> None:
    """The floor not reaching unmanaged roles is what the flags mean, not a fault.

    It lands in `notices`, never `warnings`: the CLI exits 1 on a non-empty
    `diff.warnings`, and this shape — a default policy beside an unmanaged role —
    is the one the example file documents, so a warning failed every `--yes` run
    of a valid file that had any work to do.
    """
    config = acl.parse_acl_config_text(_DEFAULT_POLICY_UNMANAGED_CONFIG)
    desired = acl._build_desired_acl_state(config)

    diff = acl.compute_diff(config, _current_state_for_config(config))

    assert desired.role_updates["Analysts"].policy_titles == ["general"]
    assert "ReadQuiltBucket" not in desired.role_updates
    unmanaged = next(
        role for role in desired.static_roles if role.name == "ReadQuiltBucket"
    )
    assert unmanaged.policy_titles == []
    assert diff.warnings == []
    assert any(
        "general" in notice and "ReadQuiltBucket" in notice for notice in diff.notices
    )
    assert any(
        "must also match a managed role's selector" in notice for notice in diff.notices
    )


def test_acl_tool_default_policy_unmanaged_notice_exits_zero(
    monkeypatch, capsys
) -> None:
    """A successful apply of the documented shape is a success, not one warning.

    Every admin call here succeeds and nothing is left undone, so the run must
    exit 0 and report the unmanaged-role note as NONFATAL. Before the note moved
    to `notices` this exited 1 on every apply that had work to do.
    """
    config = acl.parse_acl_config_text(_DEFAULT_POLICY_UNMANAGED_CONFIG)
    reconciled = _current_state_for_config(config)
    pending = replace(
        reconciled,
        managed_policies={},
        all_policies={},
        managed_roles={},
        all_roles=dict(reconciled.unmanaged_roles),
    )
    states = [pending, reconciled]
    created_roles: list[str] = []
    stack = _fake_stack(
        policies=SimpleNamespace(
            create_managed=lambda title, *, permissions: FakePolicy(
                id=f"id-{title}",
                title=title,
                managed=True,
                permissions=permissions,
                roles=[],
            ),
            list=lambda: [],
        ),
        roles=SimpleNamespace(
            create_managed=lambda name, policies: created_roles.append(name),
            list=lambda: [],
        ),
    )
    _install_acl_tool_stack(monkeypatch, stack)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: config)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "fetch_current_state",
        lambda _stack: states.pop(0) if len(states) > 1 else states[0],
    )

    result = acl_tool.main(["config.yml", "--yes"])

    captured = capsys.readouterr()
    assert result == 0
    assert created_roles == ["Analysts"]
    assert "NONFATAL: Default policies general do not reach unmanaged roles" in (
        captured.out
    )
    assert "Done." in captured.out
    assert "Warning:" not in captured.err


def test_default_policy_diff_is_idempotent_against_matching_state(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text(_DEFAULT_POLICY_CONFIG)
    config = acl.parse_acl_config(config_path)

    diff = acl.compute_diff(config, _current_state_for_config(config))

    assert diff.has_changes() is False
    assert diff.warnings == []


def test_default_policy_rejects_synthesizing_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
    config.default_policy: true
""")

    with pytest.raises(ValueError) as error:
        acl.parse_acl_config(config_path)

    message = str(error.value)
    assert (
        "policies.public.config.default_policy requires config.synthesize: false"
        in message
    )
    assert "granted to every managed role" in message


def test_default_policy_rejects_non_boolean(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  general:
    config.synthesize: false
    config.default_policy: "yes"
roles: {}
""")

    with pytest.raises(
        ValueError, match="policies.general.config.default_policy must be a boolean"
    ):
        acl.parse_acl_config(config_path)


def test_default_policy_is_rejected_on_a_role_entry(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  general:
    config.synthesize: false
roles:
  Analysts:
    config.default_policy: true
""")

    with pytest.raises(ValueError) as error:
        acl.parse_acl_config(config_path)

    message = str(error.value)
    assert "Unknown ACL fields in roles.Analysts: config.default_policy" in message
    assert (
        "Explicit roles also support the magic config.policies and "
        "config.unmanaged keys" in message
    )


def test_print_diff_verbose_shows_default_policy_on_every_role(capsys) -> None:
    desired = acl.parse_acl_config_text(_DEFAULT_POLICY_CONFIG)
    diff = acl.compute_diff(desired, _empty_current_state())

    acl.print_diff(diff, verbose=True, desired=desired)
    out = capsys.readouterr().out

    assert "    default_policy: true" in out
    assert "role internal_public (synthesized from policies public, internal)" in out
    assert "    policies: public, internal, general" in out
    assert "    policies: public, exec__inline, general" in out


def test_current_state_yaml_round_trips_default_policy_as_composed_lists(
    tmp_path: Path,
) -> None:
    """A capture replays the floor without the flag: the server never stores it."""
    source = tmp_path / "source.yml"
    source.write_text("""
policies:
  general:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [open-bucket]
  AnalystPolicy:
    config.synthesize: false
    buckets.read_write: [analyst-bucket]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
    config.default_role: true
  Observers: {}
users: {}
""")
    current = _current_state_for_config(acl.parse_acl_config(source))

    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-09-01"
    )
    exported_path = tmp_path / "exported.yml"
    exported_path.write_text(exported)
    parsed = acl.parse_acl_config(exported_path)
    diff = acl.compute_diff(parsed, current)
    payload = yaml.safe_load(exported)

    assert acl.CONFIG_DEFAULT_POLICY_KEY not in exported
    assert all(policy.default_policy is False for policy in parsed.policies)
    assert payload["roles"]["Analysts"]["config.policies"] == [
        "AnalystPolicy",
        "general",
    ]
    assert payload["roles"]["Observers"]["config.policies"] == ["general"]
    assert not diff.has_changes()
    assert diff.warnings == []


_CASCADING_DEFAULT_POLICY_CONFIG = """
policies:
  general:
    config.synthesize: false
    config.default_policy: true
    buckets.read: [open-bucket]
  public:
    sso.groups: [Everyone]
    buckets.read: [quilt-example]
    config.default_role: true
roles:
  Analysts:
    sso.groups: [Analysts]
    config.policies: [public]
"""


def _default_policy_state_with_buckets() -> acl.CurrentState:
    current = _empty_current_state()
    for bucket in ("open-bucket", "quilt-example"):
        current.buckets[bucket] = FakeBucket(name=bucket, title=bucket)
    return current


def test_default_policy_diff_composes_the_floor_onto_hand_built_server_state() -> None:
    """Idempotence against a fixture built by hand, not by the code under test.

    `_current_state_for_config` is `_build_desired_acl_state` of the same config,
    so a diff against it can only detect non-determinism. These role fixtures
    spell the composed lists out, so a floor composed in the wrong place — or
    onto the wrong roles — shows up as a role update.
    """
    config = acl.parse_acl_config_text(_DEFAULT_POLICY_CONFIG)
    policies = {
        "general": [Permission(bucket="open-bucket", level=BucketPermissionLevel.READ)],
        "public": [
            Permission(bucket="quilt-example", level=BucketPermissionLevel.READ)
        ],
        "internal": [
            Permission(bucket="quilt-dev", level=BucketPermissionLevel.READ_WRITE)
        ],
        "exec__inline": [
            Permission(
                bucket="quilt-leadership", level=BucketPermissionLevel.READ_WRITE
            )
        ],
    }
    composed = {
        "public": ["public", "general"],
        "internal_public": ["public", "internal", "general"],
        "exec": ["public", "exec__inline", "general"],
    }
    managed_policies = {
        title: FakePolicy(
            id=f"id-{title}",
            title=title,
            managed=True,
            permissions=permissions,
            roles=[],
        )
        for title, permissions in policies.items()
    }
    managed_roles = {
        name: FakeRole(
            id=f"id-{name}",
            name=name,
            policies=[
                FakePolicySummary(id=f"id-{title}", title=title) for title in titles
            ],
            permissions=[],
        )
        for name, titles in composed.items()
    }
    current = acl.CurrentState(
        buckets={
            name: FakeBucket(name=name, title=name) for name in acl.all_buckets(config)
        },
        managed_policies=managed_policies,
        unmanaged_policies={},
        all_policies=dict(managed_policies),
        managed_roles=managed_roles,
        unmanaged_roles={},
        all_roles=dict(managed_roles),
        sso_config_text=acl.build_sso_config(config),
        default_role_name="public",
    )

    diff = acl.compute_diff(config, current)

    assert diff.default_policy_titles == frozenset({"general"})
    assert diff.roles_to_create == []
    assert diff.roles_to_update == []
    assert diff.has_changes() is False
    assert diff.warnings == []


def test_compute_diff_records_default_policy_titles_without_a_change() -> None:
    config = acl.parse_acl_config_text(_CASCADING_DEFAULT_POLICY_CONFIG)

    diff = acl.compute_diff(config, _current_state_for_config(config))

    assert diff.default_policy_titles == frozenset({"general"})
    assert diff.has_changes() is False


def test_apply_acl_names_a_failed_default_policy_as_the_cause(capsys) -> None:
    """One failed default policy stops the apply; say so once, up front.

    #105 makes the floor a dependency of roles that never named it, so no role
    could be reconciled. #110 turns that from a per-role `unknown policy` cascade
    into an early return: the roles are left alone rather than created without the
    floor, which would grant less than the file asks for, and the apply never
    reaches the phases that would delete the old ones.
    """
    created_policies: list[FakePolicy] = []
    created_roles: list[str] = []

    def policy_create(title: str, *, permissions: list[Any]) -> FakePolicy:
        if title == "general":
            raise RuntimeError("NoSuchBucket: open-bucket")
        policy = FakePolicy(
            id=f"id-{title}",
            title=title,
            managed=True,
            permissions=permissions,
            roles=[],
        )
        created_policies.append(policy)
        return policy

    stack = _fake_stack(
        policies=SimpleNamespace(
            create_managed=policy_create,
            list=lambda: list(created_policies),
        ),
        roles=SimpleNamespace(
            create_managed=lambda name, policies: created_roles.append(name),
            list=lambda: [],
        ),
        sso_config=SimpleNamespace(set=lambda _text: None),
    )
    config = acl.parse_acl_config_text(_CASCADING_DEFAULT_POLICY_CONFIG)
    current = _default_policy_state_with_buckets()
    diff = acl.compute_diff(config, current)

    warnings = acl.apply_acl(stack, diff, current)

    err = capsys.readouterr().err
    assert [role.name for role in diff.roles_to_create] == ["public", "Analysts"]
    assert created_roles == []
    assert (
        "!! DEFAULT POLICY MISSING: 1 default policy blocked every managed role" in err
    )
    assert (
        "  - Policy 'general' is declared config.default_policy: true, so every "
        "managed role composes it; it does not exist, so this apply stopped "
        "before touching 2 role(s) and deleted nothing: public, Analysts." in err
    )
    assert "before any policy was deleted" in err
    assert (
        "Policy 'general' is declared config.default_policy: true, so every "
        "managed role composes it; it does not exist, so this apply stopped "
        "before touching 2 role(s) and deleted nothing: public, Analysts." in warnings
    )
    # The policy that did land still landed: stopping is not a rollback.
    assert [policy.title for policy in created_policies] == ["public"]
    # No per-role diagnosis to add: the role phase never ran.
    assert not any("unknown policy" in warning for warning in warnings)


def test_apply_acl_deletes_nothing_when_a_default_policy_is_missing(capsys) -> None:
    """The part that matters: the old state survives an unbuildable new one.

    Role deletes and policy deletes run after the role loops, so before #110 a
    missing floor skipped every role create and then deleted the roles and
    policies the file drops — the old access gone, the new access impossible.
    """
    calls: list[str] = []
    stack = _fake_stack(
        policies=SimpleNamespace(
            create_managed=lambda title, *, permissions: (_ for _ in ()).throw(
                RuntimeError("NoSuchBucket: open-bucket")
            ),
            update_managed=lambda *args, **kwargs: calls.append("policy update"),
            delete=lambda ref: calls.append(f"policy delete {ref}"),
            list=lambda: [],
        ),
        roles=SimpleNamespace(
            create_managed=lambda name, policies: calls.append(f"role create {name}"),
            update_managed=lambda *args, **kwargs: calls.append("role update"),
            delete=lambda ref: calls.append(f"role delete {ref}"),
            set_default=lambda ref: calls.append("set default"),
            list=lambda: [],
        ),
        sso_config=SimpleNamespace(set=lambda _text: calls.append("sso set")),
        users=SimpleNamespace(
            list=lambda: [],
            set_role=lambda *args, **kwargs: calls.append("set role"),
            set_admin=lambda *args, **kwargs: calls.append("set admin"),
        ),
    )
    current = _empty_current_state()
    current.managed_roles["Legacy"] = FakeRole(
        id="id-Legacy", name="Legacy", policies=[], permissions=[]
    )
    current.all_roles["Legacy"] = current.managed_roles["Legacy"]
    legacy_policy = FakePolicy(
        id="id-LegacyPolicy",
        title="LegacyPolicy",
        managed=True,
        permissions=[],
        roles=[],
    )
    current.managed_policies["LegacyPolicy"] = legacy_policy
    current.all_policies["LegacyPolicy"] = legacy_policy
    diff = acl.AclDiff(
        policies_to_create=[acl.PolicyUpdate(title="general", permissions=[])],
        roles_to_create=[acl.RoleUpdate(name="Analysts", policy_titles=["general"])],
        roles_to_delete=["Legacy"],
        policies_to_delete=["LegacyPolicy"],
        default_policy_titles=frozenset({"general"}),
    )

    warnings = acl.apply_acl(stack, diff, current)

    err = capsys.readouterr().err
    assert calls == []
    assert "!! DEFAULT POLICY MISSING" in err
    assert any("deleted nothing: Analysts" in warning for warning in warnings)


def test_apply_acl_default_policy_gate_ignores_a_run_with_no_role_changes(
    capsys,
) -> None:
    """Nothing composes the floor, so its absence blocks nothing and stops nothing."""
    calls: list[str] = []
    stack = _fake_stack(
        policies=SimpleNamespace(
            create_managed=lambda title, *, permissions: (_ for _ in ()).throw(
                RuntimeError("NoSuchBucket: open-bucket")
            ),
            delete=lambda ref: calls.append(f"policy delete {ref}"),
            list=lambda: [],
        ),
    )
    current = _empty_current_state()
    legacy_policy = FakePolicy(
        id="id-LegacyPolicy",
        title="LegacyPolicy",
        managed=True,
        permissions=[],
        roles=[],
    )
    current.managed_policies["LegacyPolicy"] = legacy_policy
    current.all_policies["LegacyPolicy"] = legacy_policy
    diff = acl.AclDiff(
        policies_to_create=[acl.PolicyUpdate(title="general", permissions=[])],
        policies_to_delete=["LegacyPolicy"],
        default_policy_titles=frozenset({"general"}),
    )

    acl.apply_acl(stack, diff, current)

    assert calls == ["policy delete id-LegacyPolicy"]
    assert "DEFAULT POLICY MISSING" not in capsys.readouterr().err


def test_apply_acl_stays_quiet_about_an_ordinary_missing_policy(capsys) -> None:
    """Only a default policy gets the block: an ordinary one costs its own roles."""
    stack = _fake_stack(
        policies=SimpleNamespace(list=lambda: []),
        roles=SimpleNamespace(create_managed=lambda name, policies: None),
    )
    diff = acl.AclDiff(
        roles_to_create=[acl.RoleUpdate(name="Analysts", policy_titles=["absent"])]
    )

    warnings = acl.apply_acl(stack, diff, _empty_current_state())

    err = capsys.readouterr().err
    assert warnings == ["Role 'Analysts' skipped: unknown policy 'absent'"]
    assert "DEFAULT POLICY MISSING" not in err


# --- downgrade detection (#89) ----------------------------------------------


def _state_with_role(
    role_name: str,
    permissions: list[Permission],
    *,
    policy_title: str = "AnalystPolicy",
) -> acl.CurrentState:
    current = _empty_current_state()
    policy = FakePolicy(
        id=f"id-{policy_title}",
        title=policy_title,
        managed=True,
        permissions=permissions,
        roles=[],
    )
    role = FakeRole(
        id=f"id-{role_name}",
        name=role_name,
        policies=[FakePolicySummary(id=policy.id, title=policy_title)],
        permissions=[],
    )
    policy.roles.append(role)
    current.managed_policies[policy_title] = policy
    current.all_policies[policy_title] = policy
    current.managed_roles[role_name] = role
    current.all_roles[role_name] = role
    return current


def _add_user(
    current: acl.CurrentState,
    name: str,
    primary: str,
    *,
    extras: tuple[str, ...] = (),
    admin: bool = False,
    sso_only: bool = False,
    email: str | None = None,
) -> None:
    user = SimpleNamespace(
        name=name,
        role=current.all_roles[primary],
        extra_roles=[current.all_roles[role] for role in extras],
        is_admin=admin,
        is_sso_only=sso_only,
    )
    # Most fakes stay email-less so the production code keeps tolerating server
    # objects that do not carry the field.
    if email is not None:
        user.email = email
    current.users.append(user)


def test_compute_diff_reports_downgrade_from_policy_shrink(tmp_path: Path) -> None:
    """Narrowing a policy downgrades every user holding the role."""
    current = _state_with_role(
        "Analysts",
        [
            Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE),
            Permission(bucket="bucket-b", level=BucketPermissionLevel.READ),
        ],
    )
    _add_user(current, "alice", "Analysts")
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert [d.name for d in diff.user_downgrades] == ["alice"]
    downgrade = diff.user_downgrades[0]
    assert downgrade.lost_permissions == ("READ_WRITE:bucket-a", "READ:bucket-b")
    assert downgrade.lost_roles == ()
    assert downgrade.admin_lost is False


def test_compute_diff_reports_no_downgrade_when_permissions_grow(
    tmp_path: Path,
) -> None:
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    _add_user(current, "alice", "Analysts")
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert diff.policies_to_update
    assert diff.user_downgrades == []


def test_compute_diff_reports_no_downgrade_for_neutral_role_reassignment(
    tmp_path: Path,
) -> None:
    """Moving a user to an equivalent role is a rename, not a downgrade."""
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    twin_policy = FakePolicy(
        id="id-TwinPolicy",
        title="TwinPolicy",
        managed=True,
        permissions=[Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)],
        roles=[],
    )
    twin = FakeRole(
        id="id-Scientists",
        name="Scientists",
        policies=[FakePolicySummary(id="id-TwinPolicy", title="TwinPolicy")],
        permissions=[],
    )
    current.managed_policies["TwinPolicy"] = twin_policy
    current.all_policies["TwinPolicy"] = twin_policy
    current.managed_roles["Scientists"] = twin
    current.all_roles["Scientists"] = twin
    _add_user(current, "alice", "Analysts")
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
  TwinPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
  Scientists:
    config.policies: [TwinPolicy]
users:
  alice:
    role: Scientists
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert [u.name for u in diff.users_to_update] == ["alice"]
    assert diff.user_downgrades == []


def test_compute_diff_reports_admin_and_extra_role_loss(tmp_path: Path) -> None:
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    extra_policy = FakePolicy(
        id="id-LeadPolicy",
        title="LeadPolicy",
        managed=True,
        permissions=[
            Permission(bucket="bucket-c", level=BucketPermissionLevel.READ_WRITE)
        ],
        roles=[],
    )
    leads = FakeRole(
        id="id-Leads",
        name="Leads",
        policies=[FakePolicySummary(id="id-LeadPolicy", title="LeadPolicy")],
        permissions=[],
    )
    current.managed_policies["LeadPolicy"] = extra_policy
    current.all_policies["LeadPolicy"] = extra_policy
    current.managed_roles["Leads"] = leads
    current.all_roles["Leads"] = leads
    _add_user(current, "alice", "Analysts", extras=("Leads",), admin=True)
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
  LeadPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-c]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
  Leads:
    config.policies: [LeadPolicy]
users:
  alice:
    role: Analysts
    admin: false
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)
    downgrade = diff.user_downgrades[0]

    assert downgrade.name == "alice"
    assert downgrade.admin_lost is True
    assert downgrade.lost_roles == ("Leads",)
    assert downgrade.lost_permissions == ("READ_WRITE:bucket-c",)
    assert "the users: entry sets admin: false" in downgrade.causes


def test_compute_diff_reports_downgrade_from_role_deletion(tmp_path: Path) -> None:
    """A user is downgraded indirectly when their role disappears."""
    current = _state_with_role(
        "Analysts",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
    )
    default_policy = FakePolicy(
        id="id-DefaultPolicy",
        title="DefaultPolicy",
        managed=True,
        permissions=[],
        roles=[],
    )
    default_role = FakeRole(
        id="id-Default",
        name="Default",
        policies=[FakePolicySummary(id="id-DefaultPolicy", title="DefaultPolicy")],
        permissions=[],
    )
    current.managed_policies["DefaultPolicy"] = default_policy
    current.all_policies["DefaultPolicy"] = default_policy
    current.managed_roles["Default"] = default_role
    current.all_roles["Default"] = default_role
    current = replace(current, default_role_name="Default")
    _add_user(current, "alice", "Analysts")
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  DefaultPolicy:
    config.synthesize: false
roles:
  Default:
    config.policies: [DefaultPolicy]
    config.default_role: true
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)
    downgrade = diff.user_downgrades[0]

    assert diff.roles_to_delete == ["Analysts"]
    assert downgrade.name == "alice"
    assert downgrade.before.primary_role == "Analysts"
    assert downgrade.after.primary_role == "Default"
    assert downgrade.lost_permissions == ("READ_WRITE:bucket-a",)
    assert "role 'Analysts' would be deleted" in downgrade.causes
    assert "falls back to the default role 'Default'" in downgrade.causes


def test_compute_diff_reports_sso_only_downgrade_from_mapping_replacement(
    tmp_path: Path,
) -> None:
    """An SSO-only user loses a role the replacement SSO no longer grants."""
    current = _state_with_role(
        "Employees",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
    )
    guest_policy = FakePolicy(
        id="id-GuestPolicy", title="GuestPolicy", managed=True, permissions=[], roles=[]
    )
    guests = FakeRole(
        id="id-Guests",
        name="Guests",
        policies=[FakePolicySummary(id="id-GuestPolicy", title="GuestPolicy")],
        permissions=[],
    )
    current.managed_policies["GuestPolicy"] = guest_policy
    current.all_policies["GuestPolicy"] = guest_policy
    current.managed_roles["Guests"] = guests
    current.all_roles["Guests"] = guests
    current = replace(current, default_role_name="Guests")
    _add_user(current, "sso-user", "Employees", sso_only=True)
    _add_user(current, "local-user", "Employees", sso_only=False)
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  GuestPolicy:
    sso.groups: [Everyone]
    config.default_role: true
  AnalystPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-a]
roles:
  Employees:
    config.policies: [AnalystPolicy]
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert diff.sso_needs_update
    # The local user keeps the role assignment; only the SSO-only user is remapped.
    assert [d.name for d in diff.user_downgrades] == ["sso-user"]
    downgrade = diff.user_downgrades[0]
    assert downgrade.after.primary_role == "GuestPolicy"
    assert downgrade.lost_permissions == ("READ_WRITE:bucket-a",)
    assert any("no SSO mapping grants role 'Employees'" in c for c in downgrade.causes)


def test_compute_diff_reports_downgrade_from_default_role_change(
    tmp_path: Path,
) -> None:
    """Changing the default role downgrades SSO-only users who fall back to it."""
    current = _state_with_role(
        "Broad",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
        policy_title="BroadPolicy",
    )
    current = replace(current, default_role_name="Broad")
    _add_user(current, "sso-user", "Broad", sso_only=True)
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  Narrow:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
  BroadPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-a]
roles:
  Broad:
    config.policies: [BroadPolicy]
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)
    downgrade = diff.user_downgrades[0]

    assert diff.default_role_needs_update
    assert diff.default_role_name == "Narrow"
    assert diff.roles_to_delete == []
    assert downgrade.name == "sso-user"
    assert downgrade.after.primary_role == "Narrow"
    assert downgrade.lost_permissions == ("READ_WRITE:bucket-a",)
    assert "falls back to the default role 'Narrow'" in downgrade.causes


def _sso_document(*mappings: tuple[str, str, str], default_role: str) -> str:
    return yaml.safe_dump(
        {
            "version": "1.0",
            "union_roles": True,
            "default_role": default_role,
            "mappings": [
                {
                    "schema": {
                        "type": "object",
                        "properties": {
                            claim: {"type": "array", "contains": {"const": value}}
                        },
                        "required": [claim],
                    },
                    "roles": [role],
                }
                for role, claim, value in mappings
            ],
        },
        sort_keys=False,
    )


def test_compute_diff_flags_undetermined_when_sso_selector_narrows(
    tmp_path: Path,
) -> None:
    """A role kept under a different selector is undetermined, not silent.

    The registry does not expose a user's IdP claims, so quiltx cannot tell
    whether they still match the replacement selector.
    """
    current = _state_with_role(
        "Analysts",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
    )
    current = replace(
        current,
        default_role_name="Analysts",
        sso_config_text=_sso_document(
            ("Analysts", "groups", "Everyone"), default_role="Analysts"
        ),
    )
    _add_user(current, "sso-user", "Analysts", sso_only=True)
    _add_user(current, "local-user", "Analysts", sso_only=False)
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-a]
roles:
  Analysts:
    sso.groups: [Engineering]
    config.policies: [AnalystPolicy]
    config.default_role: true
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert diff.sso_needs_update
    assert [d.name for d in diff.user_downgrades] == ["sso-user"]
    downgrade = diff.user_downgrades[0]
    assert downgrade.after.primary_role == "Analysts"
    assert downgrade.lost_permissions == ()
    assert downgrade.undetermined == (
        "SSO selectors for role 'Analysts' change from sso.groups=Everyone to "
        "sso.groups=Engineering; whether this user still matches them cannot "
        "be determined from the registry",
    )


def test_compute_diff_stays_quiet_when_sso_document_is_unchanged(
    tmp_path: Path,
) -> None:
    """An unchanged SSO document cannot change what an SSO-only user holds."""
    current = _state_with_role(
        "Analysts",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
    )
    current = _with_unmanaged_roles(current, "ReadQuiltBucket")
    current = replace(
        current,
        default_role_name="Analysts",
        sso_config_text=_sso_document(
            ("Analysts", "groups", "Everyone"), default_role="Analysts"
        ),
    )
    # An extra role no SSO mapping grants: unchanged SSO leaves it alone.
    _add_user(
        current, "sso-user", "Analysts", extras=("ReadQuiltBucket",), sso_only=True
    )
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-a]
roles:
  Analysts:
    sso.groups: [Everyone]
    config.policies: [AnalystPolicy]
    config.default_role: true
  ReadQuiltBucket:
    config.unmanaged: true
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert not diff.sso_needs_update
    assert diff.user_downgrades == []


def test_compute_diff_flags_undetermined_access_when_unmanaged_role_removed(
    tmp_path: Path,
) -> None:
    """Losing an IAM-backed role is reported as undetermined, not silently."""
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    current = _with_unmanaged_roles(current, "ReadWriteQuiltBucket")
    _add_user(current, "alice", "Analysts", extras=("ReadWriteQuiltBucket",))
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
users:
  alice:
    role: Analysts
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)
    downgrade = diff.user_downgrades[0]

    assert downgrade.lost_permissions == ()
    assert downgrade.lost_roles == ("ReadWriteQuiltBucket",)
    assert any("is unmanaged" in note for note in downgrade.undetermined)
    assert downgrade.is_downgrade()


def test_compute_diff_keeps_unmanaged_role_silent_when_retained(
    tmp_path: Path,
) -> None:
    """Holding an opaque role on both sides is not a downgrade."""
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    current = _with_unmanaged_roles(current, "ReadWriteQuiltBucket")
    _add_user(current, "alice", "Analysts", extras=("ReadWriteQuiltBucket",))
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
  ReadWriteQuiltBucket:
    config.unmanaged: true
users:
  alice:
    role: Analysts
    extra_roles: [ReadWriteQuiltBucket]
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert diff.user_downgrades == []


def test_export_downgrade_warnings_flag_unrepresentable_role_policies() -> None:
    """An export that cannot keep a shared inline policy warns about its users."""
    current = _empty_current_state()
    inline = FakePolicy(
        id="p-inline",
        title=f"Analysts{acl.INLINE_POLICY_SUFFIX}",
        managed=True,
        permissions=[
            Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)
        ],
        roles=[],
    )
    summary = FakePolicySummary(id="p-inline", title=inline.title)
    analysts = FakeRole(id="r1", name="Analysts", policies=[summary], permissions=[])
    observers = FakeRole(id="r2", name="Observers", policies=[summary], permissions=[])
    current.managed_policies[inline.title] = inline
    current.all_policies[inline.title] = inline
    for role in (analysts, observers):
        current.managed_roles[role.name] = role
        current.all_roles[role.name] = role
    _add_user(current, "bob", "Observers")

    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-08-17"
    )
    warnings = acl.export_downgrade_warnings(current, exported)

    assert len(warnings) == 1
    assert "user 'bob'" in warnings[0]
    assert "READ_WRITE:bucket-a" in warnings[0]
    assert "DOWNGRADE RISK: user 'bob'" in exported
    assert "would downgrade user" not in exported


def test_export_downgrade_warnings_empty_for_faithful_capture() -> None:
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    _add_user(current, "alice", "Analysts", admin=True)

    exported = acl.current_state_as_acl_yaml(
        current, catalog="catalog", captured_on="2026-08-17"
    )

    assert acl.export_downgrade_warnings(current, exported) == []
    assert "DOWNGRADE RISK" not in exported


def test_export_downgrade_warnings_report_unparseable_output() -> None:
    warnings = acl.export_downgrade_warnings(
        _empty_current_state(), "policies: [not-a-mapping]\n"
    )

    assert len(warnings) == 1
    assert "not valid input for `quiltx catalog acl`" in warnings[0]


def test_print_diff_shows_user_downgrade_block(capsys) -> None:
    diff = acl.AclDiff(
        user_downgrades=[
            acl.UserDowngrade(
                name="alice",
                before=acl.UserAccess(
                    primary_role="Analysts",
                    extra_roles=("Leads",),
                    admin=True,
                    permissions={"bucket-a": "READ_WRITE"},
                ),
                after=acl.UserAccess(primary_role="Default"),
                lost_roles=("Analysts", "Leads"),
                admin_lost=True,
                lost_permissions=("READ_WRITE:bucket-a",),
                causes=("role 'Analysts' would be deleted",),
                undetermined=("role 'Legacy' is unmanaged",),
            )
        ]
    )

    acl.print_diff(diff)
    out = capsys.readouterr().out

    assert "!! DOWNGRADE: user alice would lose access" in out
    assert "primary role: Analysts -> Default" in out
    assert "extra roles: Leads -> (none)" in out
    assert "admin: true -> false" in out
    assert "lost permissions: READ_WRITE:bucket-a" in out
    assert "cause: role 'Analysts' would be deleted" in out
    assert "undetermined: role 'Legacy' is unmanaged" in out


def test_acl_tool_dry_run_reports_downgrade(monkeypatch, capsys, tmp_path) -> None:
    current = _state_with_role(
        "Analysts",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
    )
    _add_user(current, "alice", "Analysts")
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
""")
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "apply_acl",
        lambda *a, **k: pytest.fail("dry run must not apply"),
    )

    result = acl_tool.main([str(config), "--dry-run"])
    out = capsys.readouterr().out

    assert result == 0
    assert "!! DOWNGRADE: user alice would lose access" in out
    assert "lost permissions: READ_WRITE:bucket-a" in out


def test_acl_tool_yaml_warns_about_downgrades_on_stderr(monkeypatch, capsys) -> None:
    """The warning survives `--yaml > file` because it goes to stderr."""
    current = _empty_current_state()
    inline = FakePolicy(
        id="p-inline",
        title=f"Analysts{acl.INLINE_POLICY_SUFFIX}",
        managed=True,
        permissions=[
            Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)
        ],
        roles=[],
    )
    summary = FakePolicySummary(id="p-inline", title=inline.title)
    current.managed_policies[inline.title] = inline
    current.all_policies[inline.title] = inline
    for name in ("Analysts", "Observers"):
        role = FakeRole(id=f"r-{name}", name=name, policies=[summary], permissions=[])
        current.managed_roles[name] = role
        current.all_roles[name] = role
    _add_user(current, "bob", "Observers")
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    analysis_calls = 0
    original_analysis = acl.export_downgrade_warnings

    def count_analysis(state, yaml_text):
        nonlocal analysis_calls
        analysis_calls += 1
        return original_analysis(state, yaml_text)

    monkeypatch.setattr(acl, "export_downgrade_warnings", count_analysis)

    result = acl_tool.main(["--yaml"])
    captured = capsys.readouterr()

    assert result == 0
    assert analysis_calls == 1
    assert "!! WARNING: ACL export found 1 downgrade-risk item(s):" in captured.err
    assert "user 'bob'" in captured.err
    assert "may downgrade existing users" in captured.err
    assert yaml.safe_load(captured.out)["roles"]["Observers"] == {}


def test_acl_yaml_with_warnings_reuses_neutral_general_risk(
    monkeypatch, capsys
) -> None:
    """Non-user export failures read correctly in YAML and stderr output."""
    general_risk = (
        "the generated ACL is not valid input for `quiltx catalog acl`; "
        "replaying it may change effective access"
    )
    analysis_calls = 0

    def fake_analysis(_current, _yaml_text):
        nonlocal analysis_calls
        analysis_calls += 1
        return [general_risk]

    monkeypatch.setattr(acl, "export_downgrade_warnings", fake_analysis)

    exported, warnings = acl.current_state_as_acl_yaml_with_warnings(
        _empty_current_state(), catalog="catalog", captured_on="2026-08-17"
    )
    acl_tool._print_export_downgrade_warnings(warnings)

    assert analysis_calls == 1
    assert warnings == [general_risk]
    assert f"# - DOWNGRADE RISK: {general_risk}" in exported
    assert "would downgrade the generated ACL" not in exported
    stderr = capsys.readouterr().err
    assert "found 1 downgrade-risk item(s)" in stderr
    assert "1 existing user" not in stderr
    assert general_risk in stderr


# --- users: key resolution (#104) --------------------------------------------


def _roles_for_user_tests() -> dict[str, acl.AclStaticRole]:
    return {
        "Old": acl.AclStaticRole(name="Old"),
        "New": acl.AclStaticRole(name="New"),
    }


def test_user_block_resolves_email_key_to_handle_named_account() -> None:
    """An email key reaches the handle-named account that owns it (#104)."""
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="alice@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"alice@example.com": acl.AclUserConfig(role="New")},
    )

    diff = acl.compute_diff(desired, current)

    assert diff.users_to_update == [
        acl.AclUserUpdate(name="alice", role="New", role_changed=True)
    ]
    assert diff.resolved_user_names == {"alice@example.com": "alice"}
    assert diff.notices == []


def test_user_block_resolves_username_before_email() -> None:
    """A key that names an account keeps meaning that account.

    An SSO self-registration's username is its own email, so the name and email
    indexes both answer for the same key; that self-match must resolve, not
    collide.
    """
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice@example.com", "Old", email="alice@example.com")
    _add_user(current, "alice", "Old", email="alice.alt@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"alice@example.com": acl.AclUserConfig(role="New")},
    )

    diff = acl.compute_diff(desired, current)

    assert diff.users_to_update == [
        acl.AclUserUpdate(name="alice@example.com", role="New", role_changed=True)
    ]
    assert diff.resolved_user_names == {"alice@example.com": "alice@example.com"}


def test_user_block_resolves_key_naming_an_account_over_another_email() -> None:
    """A key that names an account means that account, and the clash is reported.

    Refusing this combination would reject the tool's own `--yaml` capture, which
    keys every entry by `user.name`. Precedence decides it; the risk is a warning
    so an author who meant the other person can rekey.
    """
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice@example.com", "Old", email="alice.new@example.com")
    _add_user(current, "alice", "Old", email="alice@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"alice@example.com": acl.AclUserConfig(role="New")},
    )

    diff = acl.compute_diff(desired, current)

    assert diff.users_to_update == [
        acl.AclUserUpdate(name="alice@example.com", role="New", role_changed=True)
    ]
    assert diff.resolved_user_names == {"alice@example.com": "alice@example.com"}
    assert len(diff.warnings) == 1
    warning = diff.warnings[0]
    assert "Configured user 'alice@example.com'" in warning
    assert "the email of 'alice'" in warning
    assert "resolves to the account named 'alice@example.com'" in warning
    assert "Rekey it to the other account's username" in warning


def test_yaml_capture_of_a_username_email_collision_replays_unchanged() -> None:
    """The capture of that exact server state is still valid input (#104 fix)."""
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice@example.com", "Old", email="alice.new@example.com")
    _add_user(current, "alice", "New", email="alice@example.com")

    exported, risk_warnings = acl.current_state_as_acl_yaml_with_warnings(
        current, catalog="catalog", captured_on="2026-09-02"
    )
    replayed = acl.parse_acl_config_text(exported)
    diff = acl.compute_diff(replayed, current)

    assert set(replayed.users) == {"alice", "alice@example.com"}
    assert diff.has_changes() is False
    assert diff.users_to_update == []
    # The generic "not valid input" line stood in for every per-user finding.
    assert not any("not valid input" in warning for warning in risk_warnings)
    assert acl.export_downgrade_warnings(current, exported) == []


def test_export_downgrade_warnings_reports_per_user_despite_the_collision() -> None:
    """A real downgrade is still named per user when a key/email collision exists.

    The collision used to raise out of `compute_diff`, which
    `export_downgrade_warnings` caught and replaced with one "not valid input"
    line, discarding every per-user finding it was written to produce.
    """
    config = acl.parse_acl_config_text("""
policies:
  OldPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
  NewPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-b]
roles:
  Old:
    config.policies: [OldPolicy]
    config.default_role: true
  New:
    config.policies: [NewPolicy]
""")
    current = _current_state_for_config(config)
    _add_user(current, "alice@example.com", "Old", email="alice.new@example.com")
    _add_user(current, "alice", "New", email="alice@example.com")

    # A capture keyed by user.name, as --yaml emits, that drops role 'New'.
    captured = """
policies:
  OldPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Old:
    config.policies: [OldPolicy]
    config.default_role: true
users:
  alice:
    role: Old
    admin: false
  alice@example.com:
    role: Old
    admin: false
"""

    warnings = acl.export_downgrade_warnings(current, captured)

    assert not any("not valid input" in warning for warning in warnings)
    assert warnings == [
        "user 'alice': loses READ_WRITE:bucket-b; loses role(s) New",
    ]


def test_user_block_rejects_two_keys_addressing_one_account() -> None:
    """A handle key and an email key for one person cannot both be applied."""
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="alice@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={
            "alice": acl.AclUserConfig(role="New"),
            "alice@example.com": acl.AclUserConfig(role="Old"),
        },
    )

    with pytest.raises(ValueError) as excinfo:
        acl.compute_diff(desired, current)

    message = str(excinfo.value)
    assert "'alice' and 'alice@example.com'" in message
    assert "both address the server account 'alice'" in message
    assert "silently replace" in message


_DOWNGRADING_USER_CONFIG = """
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read_write: [bucket-a]
  ObserverPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
    config.default_role: true
  Observers:
    config.policies: [ObserverPolicy]
users:
  {key}:
    role: Observers
"""


def _analyst_observer_state() -> acl.CurrentState:
    """A server holding both roles, where Observers is strictly narrower."""
    current = _state_with_role(
        "Analysts",
        [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ_WRITE)],
    )
    policy = FakePolicy(
        id="id-ObserverPolicy",
        title="ObserverPolicy",
        managed=True,
        permissions=[Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)],
        roles=[],
    )
    role = FakeRole(
        id="id-Observers",
        name="Observers",
        policies=[FakePolicySummary(id=policy.id, title=policy.title)],
        permissions=[],
    )
    policy.roles.append(role)
    current.managed_policies[policy.title] = policy
    current.all_policies[policy.title] = policy
    current.managed_roles[role.name] = role
    current.all_roles[role.name] = role
    current.buckets["bucket-a"] = FakeBucket(name="bucket-a", title="bucket-a")
    return replace(current, default_role_name="Analysts")


def test_analyze_user_downgrades_honours_applied_user_names() -> None:
    """The older kwarg still selects which users: entries count as applied."""
    current = _analyst_observer_state()
    _add_user(current, "alice", "Analysts")
    desired = acl.parse_acl_config_text(_DOWNGRADING_USER_CONFIG.format(key="alice"))
    diff = acl.compute_diff(desired, current)

    named = acl.analyze_user_downgrades(
        desired, current, diff, applied_user_names={"alice"}
    )
    unnamed = acl.analyze_user_downgrades(
        desired, current, diff, applied_user_names=set()
    )

    assert [item.name for item in named] == ["alice"]
    assert named[0].lost_permissions == ("READ_WRITE:bucket-a",)
    assert named[0].causes == ("the users: entry reassigns roles",)
    # Nothing else in the diff reduces access, so an unnamed entry means no finding.
    assert unnamed == []


def test_analyze_user_downgrades_resolves_email_keys_by_default() -> None:
    """No kwargs must not reopen the hole #104 closed for public-API callers.

    Intersecting `desired.users` with server usernames drops every email-keyed
    entry, so the reduction it causes reads as "no entry".
    """
    current = _analyst_observer_state()
    _add_user(current, "alice", "Analysts", email="alice@example.com")
    desired = acl.parse_acl_config_text(
        _DOWNGRADING_USER_CONFIG.format(key="alice@example.com")
    )
    diff = acl.compute_diff(desired, current)

    downgrades = acl.analyze_user_downgrades(desired, current, diff)

    assert set(desired.users) == {"alice@example.com"}
    assert [item.name for item in downgrades] == ["alice"]
    assert downgrades[0].lost_permissions == ("READ_WRITE:bucket-a",)
    assert downgrades[0].causes == ("the users: entry reassigns roles",)


def test_user_block_rejects_key_matching_two_emails() -> None:
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="shared@example.com")
    _add_user(current, "alice_two", "Old", email="shared@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"shared@example.com": acl.AclUserConfig(role="New")},
    )

    with pytest.raises(
        ValueError, match="'shared@example.com' is ambiguous"
    ) as excinfo:
        acl.compute_diff(desired, current)

    assert "email of 'alice', 'alice_two'" in str(excinfo.value)


def _install_unresolvable_users_run(
    monkeypatch,
    users: dict[str, acl.AclUserConfig],
    *,
    server_emails: tuple[str, str],
) -> list[str]:
    """Wire the CLI against a `users:` block no resolution can honour.

    The config deliberately has work to do — a bucket to register and a role to
    create — because the contract under test is that the abort happens *before*
    any of it. Against a reconciled fixture the assertion would hold whether the
    run aborted first or applied everything and then failed, so a later refactor
    that turned the abort into a partial apply would still pass.

    Returns the recorder every admin mutation appends to.
    """
    recorder: list[str] = []

    def _record(label: str) -> Any:
        def _call(*_args: Any, **_kwargs: Any) -> None:
            recorder.append(label)

        return _call

    stack = _fake_stack(
        payload={"account_id": "111"},
        buckets=SimpleNamespace(add=_record("buckets.add")),
        policies=SimpleNamespace(
            create_managed=_record("policies.create_managed"),
            update_managed=_record("policies.update_managed"),
            delete=_record("policies.delete"),
            list=lambda: [],
        ),
        roles=SimpleNamespace(
            create_managed=_record("roles.create_managed"),
            update_managed=_record("roles.update_managed"),
            delete=_record("roles.delete"),
            set_default=_record("roles.set_default"),
            list=lambda: [],
        ),
        sso_config=SimpleNamespace(set=_record("sso_config.set")),
        users=SimpleNamespace(
            create=_record("users.create"),
            set_role=_record("users.set_role"),
            set_admin=_record("users.set_admin"),
            list=lambda: [],
        ),
    )
    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda *_args, **_kwargs: recorder.append("buckets.add"),
    )
    _install_acl_tool_stack(monkeypatch, stack)

    # The server holds only 'Old', so 'New' and its bucket are pending work.
    current = _current_state_for_config(
        acl.AclConfig(policies=[], roles={"Old": acl.AclStaticRole(name="Old")})
    )
    _add_user(current, "alice", "Old", email=server_emails[0])
    _add_user(current, "alice_two", "Old", email=server_emails[1])
    desired = acl.AclConfig(
        policies=[],
        roles={
            "Old": acl.AclStaticRole(name="Old"),
            "New": acl.AclStaticRole(name="New", read=["pending-bucket"]),
        },
        users=users,
    )
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: desired)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    return recorder


def test_acl_tool_ambiguous_user_key_exits_one_without_mutating(
    monkeypatch, capsys
) -> None:
    """One key, two accounts: nothing there decides, so nothing is written (#112)."""
    recorder = _install_unresolvable_users_run(
        monkeypatch,
        {"shared@example.com": acl.AclUserConfig(role="New")},
        server_emails=("shared@example.com", "shared@example.com"),
    )

    result = acl_tool.main(
        [
            "config.yml",
            "--yes",
            "--no-preflight",
            "--create-and-email-users",
        ]
    )

    err = capsys.readouterr().err
    assert result == 1
    assert recorder == []
    assert "'shared@example.com' is ambiguous" in err
    assert "email of 'alice', 'alice_two'" in err


def test_acl_tool_two_keys_for_one_account_exit_one_without_mutating(
    monkeypatch, capsys
) -> None:
    """A handle key and an email key for one person would silently overwrite (#112)."""
    recorder = _install_unresolvable_users_run(
        monkeypatch,
        {
            "alice": acl.AclUserConfig(role="New"),
            "alice@example.com": acl.AclUserConfig(role="Old"),
        },
        server_emails=("alice@example.com", "other@example.com"),
    )

    result = acl_tool.main(
        [
            "config.yml",
            "--yes",
            "--no-preflight",
            "--create-and-email-users",
        ]
    )

    err = capsys.readouterr().err
    assert result == 1
    assert recorder == []
    assert "'alice' and 'alice@example.com'" in err
    assert "both address the server account 'alice'" in err


def test_user_block_matches_email_case_insensitively() -> None:
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="Alice@Example.COM")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"alice@example.com": acl.AclUserConfig(role="New")},
    )

    diff = acl.compute_diff(desired, current)

    assert [update.name for update in diff.users_to_update] == ["alice"]


def test_user_block_notices_key_matching_neither_name_nor_email() -> None:
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="alice@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"nobody@example.com": acl.AclUserConfig(role="New")},
    )

    diff = acl.compute_diff(desired, current)

    assert diff.users_to_update == []
    assert diff.resolved_user_names == {}
    assert diff.notices == [
        "Configured user 'nobody@example.com' does not exist on the server; skipping."
    ]


def test_apply_sends_server_username_for_email_keyed_user() -> None:
    """The SDK is only ever given a username, never the key that resolved."""
    role_calls: list[Any] = []
    admin_calls: list[Any] = []
    stack = _fake_stack(
        users=SimpleNamespace(
            set_role=lambda *args, **kwargs: role_calls.append((args, kwargs)),
            set_admin=lambda *args: admin_calls.append(args),
        )
    )
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="alice@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"alice@example.com": acl.AclUserConfig(role="New", admin=True)},
    )

    diff = acl.compute_diff(desired, current)
    warnings = acl.apply_acl(stack, diff, current)

    assert warnings == []
    assert role_calls == [
        (("alice", "New"), {"extra_roles": None, "append": False}),
    ]
    assert admin_calls == [("alice", True)]


def test_email_keyed_user_entry_reports_admin_downgrade(tmp_path: Path) -> None:
    """Downgrade analysis sees an email-keyed entry, which matches by username."""
    current = _state_with_role(
        "Analysts", [Permission(bucket="bucket-a", level=BucketPermissionLevel.READ)]
    )
    _add_user(current, "alice", "Analysts", admin=True, email="alice@example.com")
    config = tmp_path / "acl.yml"
    config.write_text("""
policies:
  AnalystPolicy:
    config.synthesize: false
    buckets.read: [bucket-a]
roles:
  Analysts:
    config.policies: [AnalystPolicy]
users:
  alice@example.com:
    role: Analysts
    admin: false
""")

    diff = acl.compute_diff(acl.parse_acl_config(config), current)

    assert diff.users_to_update == [
        acl.AclUserUpdate(
            name="alice", role="Analysts", admin=False, admin_changed=True
        )
    ]
    assert [downgrade.name for downgrade in diff.user_downgrades] == ["alice"]
    downgrade = diff.user_downgrades[0]
    assert downgrade.admin_lost is True
    assert "the users: entry sets admin: false" in downgrade.causes


def test_print_diff_verbose_labels_resolved_email_key(capsys) -> None:
    roles = _roles_for_user_tests()
    current = _current_state_for_config(acl.AclConfig(policies=[], roles=roles))
    _add_user(current, "alice", "Old", email="alice@example.com")
    desired = acl.AclConfig(
        policies=[],
        roles=roles,
        users={"alice@example.com": acl.AclUserConfig(role="New")},
    )

    diff = acl.compute_diff(desired, current)
    acl.print_diff(diff, verbose=True, desired=desired, current=current)

    assert "~ user alice@example.com -> alice" in capsys.readouterr().out


def test_register_bucket_reports_grants_it_keeps(monkeypatch, capsys) -> None:
    """Two stacks sharing a bucket must not evict each other silently (issue #102)."""
    from quiltx import bucket as bucket_lib

    plan = SimpleNamespace(
        sns_topic_arn="arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications",
        principals_before=("arn:aws:iam::712023778557:root",),
        principals_removed=(),
    )

    class Session:
        def client(self, service: str, region_name: str | None = None):
            if service == "sts":
                return SimpleNamespace(
                    get_caller_identity=lambda: {"Account": "111122223333"}
                )
            return object()

    monkeypatch.setattr(
        bucket_lib,
        "resolve_bucket_session",
        lambda *args, **kwargs: (Session(), object(), "us-west-2", "prod"),
    )
    monkeypatch.setattr(
        bucket_lib, "build_bucket_preparation_plan", lambda *args, **kwargs: plan
    )
    monkeypatch.setattr(
        bucket_lib, "apply_bucket_preparation", lambda candidate, **kwargs: None
    )
    stack = _fake_stack(buckets=SimpleNamespace(add=lambda **kwargs: None))

    acl._register_bucket_with_retry(stack, "bucket-a", "867344438354", assume_yes=True)

    err = capsys.readouterr().err
    assert "keeping existing grants for arn:aws:iam::712023778557:root" in err


# --- per-bucket no-preflight (#96) -------------------------------------------


def test_parse_acl_config_accepts_per_bucket_no_preflight(tmp_path: Path) -> None:
    """A bucket prepared owner-side is declared, not passed on the command line."""
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies: {}
roles:
  SierraGeneralRole:
    buckets.read_write: [sierra-general]
buckets:
  sierra-general:
    config.no_preflight: true
""")

    config = acl.parse_acl_config(config_path)

    assert config.buckets == {"sierra-general": acl.AclBucketConfig(no_preflight=True)}
    assert acl.all_buckets(config) == {"sierra-general"}


def test_parse_acl_config_registers_declared_bucket_without_any_grant() -> None:
    """A `buckets:` entry references the bucket on its own."""
    config = acl.parse_acl_config_text("""
policies: {}
roles: {}
buckets:
  sierra-general:
    config.no_preflight: true
  plain-bucket: {}
""")

    assert acl.all_buckets(config) == {"sierra-general", "plain-bucket"}
    assert config.buckets["plain-bucket"].no_preflight is False


def test_parse_acl_config_rejects_unknown_bucket_field() -> None:
    with pytest.raises(ValueError, match="Unknown fields in buckets.sierra-general"):
        acl.parse_acl_config_text("""
policies: {}
roles: {}
buckets:
  sierra-general:
    config.no_prefight: true
""")


def test_parse_acl_config_rejects_non_boolean_no_preflight() -> None:
    with pytest.raises(
        ValueError,
        match="buckets.sierra-general.config.no_preflight must be a boolean",
    ):
        acl.parse_acl_config_text("""
policies: {}
roles: {}
buckets:
  sierra-general:
    config.no_preflight: yes-please
""")


def test_parse_acl_config_rejects_non_mapping_buckets_block() -> None:
    with pytest.raises(ValueError, match="'buckets' must be a mapping"):
        acl.parse_acl_config_text("""
policies: {}
roles: {}
buckets: [sierra-general]
""")


def test_parse_acl_config_rejects_non_mapping_bucket_entry() -> None:
    with pytest.raises(ValueError, match="Bucket 'sierra-general' must be a mapping"):
        acl.parse_acl_config_text("""
policies: {}
roles: {}
buckets:
  sierra-general: true
""")


def test_compute_diff_records_per_bucket_no_preflight() -> None:
    desired = acl.parse_acl_config_text("""
policies: {}
roles:
  SierraGeneralRole:
    buckets.read_write: [sierra-general, owned-bucket]
buckets:
  sierra-general:
    config.no_preflight: true
  owned-bucket:
    config.no_preflight: false
""")

    diff = acl.compute_diff(desired, _empty_current_state())

    assert diff.buckets_to_add == ["owned-bucket", "sierra-general"]
    assert diff.no_preflight_buckets == frozenset({"sierra-general"})


def test_apply_acl_no_preflight_applies_per_bucket_not_globally(monkeypatch) -> None:
    """The marked bucket skips preflight; the rest of the apply is unchanged."""
    graphql_only: list[str] = []
    prepared: list[str] = []

    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda _stack, bucket, *, title=None: graphql_only.append(bucket),
    )
    monkeypatch.setattr(
        acl,
        "_register_bucket_with_retry",
        lambda _stack, bucket, _account, *, assume_yes: prepared.append(bucket),
    )
    stack = _fake_stack(payload={"account_id": "111"})

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(
            buckets_to_add=["owned-bucket", "sierra-general"],
            no_preflight_buckets=frozenset({"sierra-general"}),
        ),
        _empty_current_state(),
    )

    assert warnings == []
    assert graphql_only == ["sierra-general"]
    assert prepared == ["owned-bucket"]


def test_apply_acl_per_bucket_no_preflight_needs_no_control_account(
    monkeypatch,
) -> None:
    """No local AWS work means no control-account metadata to demand."""
    graphql_only: list[str] = []

    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda _stack, bucket, *, title=None: graphql_only.append(bucket),
    )
    monkeypatch.setattr(
        acl,
        "_register_bucket_with_retry",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("preflight must not run for a no-preflight bucket")
        ),
    )
    stack = _fake_stack(payload={"region": "us-east-1"})

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(
            buckets_to_add=["sierra-general"],
            no_preflight_buckets=frozenset({"sierra-general"}),
        ),
        _empty_current_state(),
    )

    assert warnings == []
    assert graphql_only == ["sierra-general"]


def test_apply_acl_global_no_preflight_flag_covers_unmarked_buckets(
    monkeypatch,
) -> None:
    """The CLI flag stays a global override of the per-bucket declaration."""
    graphql_only: list[str] = []

    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda _stack, bucket, *, title=None: graphql_only.append(bucket),
    )
    monkeypatch.setattr(
        acl,
        "_register_bucket_with_retry",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("--no-preflight must skip preparation for every bucket")
        ),
    )
    stack = _fake_stack(payload={"account_id": "111"})

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(
            buckets_to_add=["owned-bucket", "sierra-general"],
            no_preflight_buckets=frozenset({"sierra-general"}),
        ),
        _empty_current_state(),
        no_preflight=True,
    )

    assert warnings == []
    assert graphql_only == ["owned-bucket", "sierra-general"]


def test_apply_acl_prints_prominent_block_for_failed_bucket(
    monkeypatch, capsys
) -> None:
    """A bucket that did not register is named in its own block, with the reason."""
    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda _stack, bucket, *, title=None: (_ for _ in ()).throw(
            RuntimeError("AccessDenied on GetBucketLocation")
        ),
    )
    stack = _fake_stack(payload={"account_id": "111"})

    warnings = acl.apply_acl(
        stack,
        acl.AclDiff(
            buckets_to_add=["sierra-general"],
            no_preflight_buckets=frozenset({"sierra-general"}),
        ),
        _empty_current_state(),
    )

    err = capsys.readouterr().err
    assert warnings == [
        "Bucket 'sierra-general' was not registered: AccessDenied on GetBucketLocation"
    ]
    assert "!! BUCKET REGISTRATION FAILED: 1 bucket(s) not registered:" in err
    assert "  - sierra-general: AccessDenied on GetBucketLocation" in err
    assert "config.no_preflight" in err


def test_acl_tool_exits_nonzero_when_bucket_registration_fails(
    monkeypatch, capsys
) -> None:
    desired = acl.parse_acl_config_text("""
policies: {}
roles: {}
buckets:
  sierra-general:
    config.no_preflight: true
""")
    current = _empty_current_state()
    _install_acl_tool_stack(monkeypatch, _fake_stack(payload={"account_id": "111"}))
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: desired)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)
    monkeypatch.setattr(
        "quiltx.bucket.add_bucket_without_preflight",
        lambda _stack, bucket, *, title=None: (_ for _ in ()).throw(
            RuntimeError("AccessDenied")
        ),
    )

    result = acl_tool.main(["config.yml", "--yes"])

    err = capsys.readouterr().err
    assert result == 1
    assert "!! BUCKET REGISTRATION FAILED: 1 bucket(s) not registered:" in err
    assert "  - sierra-general: AccessDenied" in err
    assert "!! 1 bucket(s) are still not registered: sierra-general" in err
    assert "Done with 1 warning(s) and 1 unregistered bucket(s)." in err


def test_acl_tool_dry_run_names_per_bucket_no_preflight_buckets(
    monkeypatch, capsys
) -> None:
    desired = acl.parse_acl_config_text("""
policies: {}
roles:
  Analysts:
    buckets.read: [owned-bucket]
buckets:
  sierra-general:
    config.no_preflight: true
""")
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: desired)
    monkeypatch.setattr(
        acl_tool.acl_lib, "fetch_current_state", lambda _stack: _empty_current_state()
    )
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "apply_acl",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("apply_acl should not be called")
        ),
    )

    result = acl_tool.main(["config.yml", "--dry-run"])

    out = capsys.readouterr().out
    assert result == 0
    assert "1 new bucket(s) would be registered via GraphQL only" in out
    assert "- sierra-general (buckets.sierra-general.config.no_preflight)" in out
    assert "- owned-bucket" not in out


def test_acl_tool_apply_records_per_bucket_no_preflight_buckets(
    monkeypatch, capsys
) -> None:
    """A --yes CI log has to say which buckets skipped local AWS verification."""
    desired = acl.parse_acl_config_text("""
policies: {}
roles:
  Analysts:
    buckets.read: [owned-bucket]
buckets:
  sierra-general:
    config.no_preflight: true
""")
    states = [_empty_current_state(), _current_state_for_config(desired)]
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: desired)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "fetch_current_state",
        lambda _stack: states.pop(0) if len(states) > 1 else states[0],
    )
    monkeypatch.setattr(acl_tool.acl_lib, "apply_acl", lambda *_args, **_kwargs: [])

    result = acl_tool.main(["config.yml", "--yes"])

    out = capsys.readouterr().out
    assert result == 0
    assert "1 new bucket(s) will be registered via GraphQL only" in out
    assert "- sierra-general (buckets.sierra-general.config.no_preflight)" in out
    assert "- owned-bucket" not in out


# --- --create-and-email-users (#106) -----------------------------------------


_ROSTER_CONFIG = """
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
  leads:
    sso.email: [lead@example.com]
    buckets.read_write: [bucket-a]
roles:
  Analysts:
    sso.email: [alice@example.com, bob@example.com]
    sso.hd: [example.com]
    config.policies: [public]
"""


def _roster_config() -> acl.AclConfig:
    return acl.parse_acl_config_text(_ROSTER_CONFIG)


def test_sso_email_roster_reads_static_and_synthesized_roles() -> None:
    """Only sso.email names individuals, and the role comes from the nesting."""
    roster = acl.sso_email_roster(_roster_config())

    assert roster == {
        "lead@example.com": ["leads_public"],
        "alice@example.com": ["Analysts"],
        "bob@example.com": ["Analysts"],
    }


def test_sso_email_roster_ignores_group_and_domain_selectors() -> None:
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Domain:
    sso.hd: [example.com]
    config.policies: [public]
""")

    assert acl.sso_email_roster(config) == {}


def test_sso_email_roster_folds_case_variants_into_one_entry() -> None:
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.email: [Alice@Example.com]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Leads:
    sso.email: [alice@example.com]
    config.policies: [public]
""")

    assert acl.sso_email_roster(config) == {"Alice@Example.com": ["public", "Leads"]}


@pytest.mark.parametrize(
    "address, expected",
    [
        ("alice@example.com", "alice_example_com"),
        ("Alice.Smith@Example.COM", "alice_smith_example_com"),
        ("a+tag@example.com", "a_tag_example_com"),
        # A leading digit is legal in a local part and illegal in a username.
        ("7t9@example.com", "u_7t9_example_com"),
        ("_leading@example.com", "u__leading_example_com"),
        ("ernő@example.com", "ern__example_com"),
        (("l" * 70) + "@example.com", "l" * 64),
    ],
)
def test_derive_username_folds_an_address_into_a_handle(
    address: str, expected: str
) -> None:
    """The mapping itself: fold to the grammar, keep the domain, truncate to 64."""
    assert acl.derive_username(address) == expected


@pytest.mark.parametrize(
    "address",
    [
        "alice@example.com",
        "7t9@example.com",
        "_@example.com",
        "@",
        "!!!",
        "ernő@example.com",
        "",
        "   ",
        ("x" * 200) + "@example.com",
        "9" * 200,
    ],
)
def test_derive_username_always_satisfies_the_registry_grammar(address: str) -> None:
    """The invariant the caller relies on to skip a pre-flight name check.

    `plan_user_creations` sends the derived name straight to the registry, and a
    rejected creation is a wasted round trip whose mail may already have gone out
    for the addresses before it. Rather than re-validate a value it just built,
    the derivation is total: pinned here over the shapes that could break it —
    empty, blank, leading digit, leading underscore, punctuation only, non-ASCII,
    and long enough that truncation is in play.
    """
    name = acl.derive_username(address)

    assert acl.USERNAME_PATTERN.match(name) is not None
    assert 1 <= len(name) <= acl.USERNAME_MAX_LENGTH


def test_plan_user_creations_folds_ordinary_addresses_into_handles() -> None:
    """The headline case: a roster of ordinary addresses is now creatable.

    `quilt3.admin.users.create` requires `name`, so quiltx cannot let the
    registry derive `email[:64]` and must supply a handle the grammar accepts.
    The account is still matched by email when its owner first signs in through
    SSO, so the handle is an administrative label rather than the identity.
    """
    config = _roster_config()

    plan = acl.plan_user_creations(config, _current_state_for_config(config))

    assert plan.warnings == ()
    assert plan.notices == ()
    assert plan.existing == ()
    assert plan.creations == (
        acl.UserCreation(
            name="lead_example_com", email="lead@example.com", role="leads_public"
        ),
        acl.UserCreation(
            name="alice_example_com", email="alice@example.com", role="Analysts"
        ),
        acl.UserCreation(
            name="bob_example_com", email="bob@example.com", role="Analysts"
        ),
    )


def test_plan_user_creations_refuses_an_address_that_looks_like_a_rename() -> None:
    """An address nobody holds is not proof of a new person.

    The live case this comes from: an account existed as `robbyqbutler` /
    `robbyqbutler@protonmail.com` and the roster was edited to
    `robbyqbutler@pm.me`. Neither index matches — the derived handle
    `robbyqbutler_pm_me` clashes with nothing either — so the address read as a
    brand-new person and a second account would have been created and mailed.
    quiltx never calls `set_email`, so nothing later merges them.
    """
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Analysts:
    sso.email: [robbyqbutler@pm.me]
    config.policies: [public]
""")
    current = _current_state_for_config(config)
    _add_user(current, "robbyqbutler", "Analysts", email="robbyqbutler@protonmail.com")

    plan = acl.plan_user_creations(config, current)

    assert plan.creations == ()
    assert plan.existing == ()
    assert len(plan.warnings) == 1
    warning = plan.warnings[0]
    assert "Roster address 'robbyqbutler@pm.me' has no account" in warning
    assert "local part 'robbyqbutler' is already used by" in warning
    assert "'robbyqbutler' (email robbyqbutler@protonmail.com)" in warning
    assert "never edits an account's email" in warning
    assert "Set the existing account's email to this address" in warning


def test_plan_user_creations_matches_a_rename_against_an_email_shaped_username() -> (
    None
):
    """An SSO self-registration carries the old address as its username.

    `user.name` is `email[:64]` for accounts that signed themselves up, so the
    local part has to be read out of the username too, not just out of `email`.
    """
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Analysts:
    sso.email: [alice@newmail.example]
    config.policies: [public]
""")
    current = _current_state_for_config(config)
    _add_user(current, "alice@example.com", "Analysts")

    plan = acl.plan_user_creations(config, current)

    assert plan.creations == ()
    assert len(plan.warnings) == 1
    assert "local part 'alice' is already used by 'alice@example.com'" in (
        plan.warnings[0]
    )


def test_plan_user_creations_still_onboards_an_unrelated_local_part() -> None:
    """The rename check must not block ordinary onboarding.

    Only an address whose local part an existing account already uses is refused;
    a roster of genuinely new people is created as before.
    """
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "carol", "Analysts", email="carol@example.com")

    plan = acl.plan_user_creations(config, current)

    assert plan.warnings == ()
    assert [creation.name for creation in plan.creations] == [
        "lead_example_com",
        "alice_example_com",
        "bob_example_com",
    ]


def test_plan_user_creations_refuses_two_addresses_deriving_one_username() -> None:
    """Folding is not injective, and the clash is refused rather than resolved.

    '.' and '+' both fold to '_', so two distinct people can want one handle.
    Only one account can hold it, so quiltx creates neither: picking one would
    silently onboard one person and drop the other, and the mail for the winner
    cannot be recalled. Both addresses are refused, so both are counted.
    """
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Analysts:
    sso.email: [a.b@example.com, a+b@example.com]
    config.policies: [public]
""")

    plan = acl.plan_user_creations(config, _current_state_for_config(config))

    assert plan.creations == ()
    assert len(plan.warnings) == 2
    assert "Roster address 'a.b@example.com' derives username 'a_b_example_com'" in (
        plan.warnings[0]
    )
    assert "also derived by 'a+b@example.com'" in plan.warnings[0]
    assert "also derived by 'a.b@example.com'" in plan.warnings[1]
    for warning in plan.warnings:
        assert "not created" in warning
        assert "will not decide which of these addresses gets it" in warning


def test_plan_user_creations_refuses_a_handle_another_account_holds() -> None:
    """A derived handle an unrelated account already uses is somebody else's name."""
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "alice_example_com", "public", email="squatter@example.com")

    plan = acl.plan_user_creations(config, current)

    assert [creation.email for creation in plan.creations] == [
        "lead@example.com",
        "bob@example.com",
    ]
    assert len(plan.warnings) == 1
    assert (
        "Roster address 'alice@example.com' derives username 'alice_example_com', "
        "which already belongs to a different account (email squatter@example.com)"
    ) in plan.warnings[0]


def test_plan_user_creations_skips_address_held_as_an_email() -> None:
    """An account under an unrelated handle still owns the address it answers for.

    The handle quiltx would derive is not the handle a human picked, so only the
    email index can find this account — which is why existence is decided by
    email before username.
    """
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "asmith", "Analysts", email="alice@example.com")

    plan = acl.plan_user_creations(config, current)

    assert plan.existing == ("alice@example.com",)
    assert [creation.email for creation in plan.creations] == [
        "lead@example.com",
        "bob@example.com",
    ]


def test_plan_user_creations_skips_address_held_as_a_username() -> None:
    """An SSO self-registration is named `email[:64]`, so the address is the name."""
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "alice@example.com", "Analysts")

    plan = acl.plan_user_creations(config, current)

    assert plan.existing == ("alice@example.com",)
    assert [creation.email for creation in plan.creations] == [
        "lead@example.com",
        "bob@example.com",
    ]


def test_plan_user_creations_reports_an_ambiguous_address_as_held() -> None:
    """Two accounts answering for one address is held, and said out loud.

    Not a raise: a roster is keyed by email and cannot be rekeyed, so aborting
    the apply over an address needing no action would be wrong. Not silence
    either, or the address reads as ordinarily onboarded. A notice and not a
    warning, because the address is already counted in `existing`: reporting it
    as uncreatable would name it twice and fail a run with nothing to do.
    """
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "alice", "Analysts", email="alice@example.com")
    _add_user(current, "alice_two", "Analysts", email="alice@example.com")

    plan = acl.plan_user_creations(config, current)

    assert plan.existing == ("alice@example.com",)
    assert [creation.email for creation in plan.creations] == [
        "lead@example.com",
        "bob@example.com",
    ]
    assert plan.warnings == ()
    assert len(plan.notices) == 1
    notice = plan.notices[0]
    assert "Roster address 'alice@example.com'" in notice
    assert "the email of 'alice', 'alice_two'" in notice
    assert "no account was created for it" in notice
    assert "cannot be rekeyed by username" in notice


def test_plan_user_creations_skips_an_address_whose_role_is_not_on_the_server() -> None:
    """An unmanaged role quiltx will never create cannot receive a new account."""
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  LegacyIam:
    config.unmanaged: true
    sso.email: [legacy@example.com]
""")
    current = _current_state_for_config(config)
    current.unmanaged_roles.pop("LegacyIam")
    current.all_roles.pop("LegacyIam")

    plan = acl.plan_user_creations(config, current)

    assert plan.creations == ()
    assert plan.existing == ()
    assert len(plan.warnings) == 1
    warning = plan.warnings[0]
    assert "Roster address 'legacy@example.com'" in warning
    assert "names role(s) LegacyIam" in warning
    assert "the server does not hold" in warning
    assert "Unmanaged roles are never created" in warning


def test_plan_user_creations_creates_into_an_existing_unmanaged_role() -> None:
    """The selector grants that role at first login anyway, so pre-creating is safe.

    The permissions it confers are IAM-backed, which the downgrade analysis
    reports as undetermined; that is a property of the role, not of the creation.
    """
    config = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  LegacyIam:
    config.unmanaged: true
    sso.email: [legacy@example.com]
""")
    current = _current_state_for_config(config)

    plan = acl.plan_user_creations(config, current)

    assert "LegacyIam" in current.unmanaged_roles
    assert plan.warnings == ()
    assert plan.creations == (
        acl.UserCreation(
            name="legacy_example_com",
            email="legacy@example.com",
            role="LegacyIam",
        ),
    )


def test_plan_user_creations_allows_a_managed_role_this_run_creates() -> None:
    """A dry run must not report a missing role that the same apply creates."""
    config = _roster_config()

    plan = acl.plan_user_creations(config, _empty_current_state())

    assert plan.warnings == ()
    assert [creation.role for creation in plan.creations] == [
        "leads_public",
        "Analysts",
        "Analysts",
    ]


def test_plan_user_creations_truncates_derived_username_to_64_characters() -> None:
    """The registry's length limit is enforced client-side, before the round trip.

    A local part that fills the limit on its own pushes the folded domain past the
    cut, so the handle carries none of it — which is also how truncation turns a
    total mapping into a colliding one, the case the next test covers.
    """
    long_address = ("l" * 70) + "@example.com"
    config = acl.parse_acl_config_text(f"""
policies:
  public:
    sso.email: [{long_address}]
    buckets.read: [bucket-a]
    config.default_role: true
roles: {{}}
""")

    plan = acl.plan_user_creations(config, _current_state_for_config(config))

    assert len(long_address) == 82
    assert plan.warnings == ()
    assert plan.creations == (
        acl.UserCreation(name="l" * 64, email=long_address, role="public"),
    )
    assert len(plan.creations[0].name) == 64


def test_plan_user_creations_refuses_truncated_username_collision() -> None:
    """Truncation can land on somebody else's username; that address is skipped."""
    long_address = ("l" * 70) + "@example.com"
    config = acl.parse_acl_config_text(f"""
policies:
  public:
    sso.email: [{long_address}]
    buckets.read: [bucket-a]
    config.default_role: true
roles: {{}}
""")
    current = _current_state_for_config(config)
    _add_user(current, long_address[:64], "public", email="squatter@example.com")

    plan = acl.plan_user_creations(config, current)

    assert plan.creations == ()
    assert len(plan.warnings) == 1
    warning = plan.warnings[0]
    assert f"Roster address '{long_address}'" in warning
    assert f"derives username '{long_address[:64]}'" in warning
    assert "email squatter@example.com" in warning
    assert "not created" in warning


def test_plan_user_creations_makes_last_matching_role_active() -> None:
    """One person on several rungs starts where their first login would leave them."""
    address = "alice@example.com"
    config = acl.parse_acl_config_text(f"""
policies:
  public:
    sso.email: [{address}]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Leads:
    sso.email: [{address}]
    config.policies: [public]
  Execs:
    sso.email: [{address}]
    config.policies: [public]
""")

    plan = acl.plan_user_creations(config, _current_state_for_config(config))

    assert plan.creations == (
        acl.UserCreation(
            name="alice_example_com",
            email=address,
            role="Execs",
            extra_roles=("public", "Leads"),
        ),
    )


def test_create_roster_users_sends_name_email_and_role() -> None:
    """The creation machinery on its own: what reaches `users.create`.

    The `UserCreation` objects are built by hand rather than planned, so a change
    to `derive_username` cannot quietly rewrite what this test asserts is sent.
    """
    create_calls: list[Any] = []
    stack = _fake_stack(
        users=SimpleNamespace(
            create=lambda *args, **kwargs: create_calls.append((args, kwargs))
        )
    )

    warnings = acl.create_roster_users(
        stack,
        (
            acl.UserCreation(
                name="alice",
                email="alice@example.com",
                role="Analysts",
                extra_roles=("public",),
            ),
            acl.UserCreation(name="bob", email="bob@example.com", role="Analysts"),
        ),
    )

    assert warnings == []
    assert create_calls == [
        (
            ("alice", "alice@example.com", "Analysts"),
            {"extra_roles": ["public"]},
        ),
        (
            ("bob", "bob@example.com", "Analysts"),
            {"extra_roles": None},
        ),
    ]


_ROSTER_CREATIONS = (
    acl.UserCreation(name="lead", email="lead@example.com", role="leads_public"),
    acl.UserCreation(name="alice", email="alice@example.com", role="Analysts"),
    acl.UserCreation(name="bob", email="bob@example.com", role="Analysts"),
)


def _stub_creation_plan(
    monkeypatch, creations: tuple[acl.UserCreation, ...] = _ROSTER_CREATIONS
) -> None:
    """Hand the CLI a plan outright, so the seam after it can be tested alone.

    These tests are about what happens once a plan exists — the prompt, the cap,
    the phase ordering, the per-address failure path — and several of them need a
    creation count the real roster does not have. `derive_username` has its own
    coverage, and `test_acl_tool_creates_the_handles_the_plan_derived` runs the
    two together unstubbed.
    """
    plan = acl.UserCreationPlan(creations=creations)
    monkeypatch.setattr(
        acl_tool.acl_lib, "plan_user_creations", lambda *_args, **_kwargs: plan
    )


def _install_roster_run(
    monkeypatch,
    *,
    current: acl.CurrentState | None = None,
    create: Any = None,
    config: acl.AclConfig | None = None,
) -> tuple[acl.CurrentState, list[Any]]:
    """Wire acl_tool against a roster config whose ACL state is already applied."""
    create_calls: list[Any] = []

    def _create(*args: Any, **kwargs: Any) -> None:
        create_calls.append((args, kwargs))
        if create is not None:
            create(*args, **kwargs)

    config = _roster_config() if config is None else config
    state = current if current is not None else _current_state_for_config(config)
    stack = _fake_stack(users=SimpleNamespace(create=_create))
    _install_acl_tool_stack(monkeypatch, stack)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: config)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: state)
    return state, create_calls


def _install_pending_roster_run(
    monkeypatch, *, applied: list[str], create_calls: list[Any]
) -> None:
    """Wire acl_tool against a roster config that still has ACL changes to apply.

    The reconciled fixture cannot show the two-prompt ordering: with nothing to
    apply there is only ever one prompt.
    """

    def _create(*args: Any, **kwargs: Any) -> None:
        create_calls.append((args, kwargs))

    config = _roster_config()
    reconciled = _current_state_for_config(config)
    pending = replace(
        reconciled,
        managed_roles={
            name: role
            for name, role in reconciled.managed_roles.items()
            if name != "Analysts"
        },
        all_roles={
            name: role
            for name, role in reconciled.all_roles.items()
            if name != "Analysts"
        },
    )
    states = [pending, reconciled]
    stack = _fake_stack(users=SimpleNamespace(create=_create))
    _install_acl_tool_stack(monkeypatch, stack)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: config)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "fetch_current_state",
        lambda _stack: states.pop(0) if len(states) > 1 else states[0],
    )

    def _apply(*_args: Any, **_kwargs: Any) -> list[str]:
        applied.append("apply")
        return []

    monkeypatch.setattr(acl_tool.acl_lib, "apply_acl", _apply)


def test_acl_tool_creates_nobody_without_the_flag(monkeypatch, capsys) -> None:
    """The default is unchanged: a reconciled file with a roster is a no-op."""
    _, create_calls = _install_roster_run(monkeypatch)

    result = acl_tool.main(["config.yml", "--yes"])

    assert result == 0
    assert create_calls == []
    assert "CREATE AND EMAIL" not in capsys.readouterr().out


def test_acl_tool_prompts_for_the_apply_and_the_creations_separately(
    monkeypatch, capsys
) -> None:
    """Creating accounts is a second irreversible action, so it asks a second time."""
    applied: list[str] = []
    create_calls: list[Any] = []
    prompts: list[str] = []
    _install_pending_roster_run(monkeypatch, applied=applied, create_calls=create_calls)
    _stub_creation_plan(monkeypatch)

    def _accept(prompt: str) -> str:
        prompts.append(prompt)
        return "y"

    monkeypatch.setattr("builtins.input", _accept)

    result = acl_tool.main(["config.yml", "--create-and-email-users"])

    out = capsys.readouterr().out
    assert result == 0
    assert prompts == [
        "Apply ACL changes? [y/N]: ",
        "Create and email 3 account(s)? [y/N]: ",
    ]
    assert applied == ["apply"]
    assert len(create_calls) == 3
    assert out.index("Applying...") < out.index("!! CREATE AND EMAIL")


def test_acl_tool_declining_the_apply_prompt_creates_nobody(
    monkeypatch, capsys
) -> None:
    """The creation prompt is never reached, so the mail is never sent."""
    applied: list[str] = []
    create_calls: list[Any] = []
    prompts: list[str] = []
    _install_pending_roster_run(monkeypatch, applied=applied, create_calls=create_calls)

    def _decline(prompt: str) -> str:
        prompts.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", _decline)

    result = acl_tool.main(["config.yml", "--create-and-email-users"])

    out = capsys.readouterr().out
    assert result == 1
    assert prompts == ["Apply ACL changes? [y/N]: "]
    assert applied == []
    assert create_calls == []
    assert "CREATE AND EMAIL" not in out
    assert "Aborted." in out


def test_acl_tool_dry_run_names_addresses_without_creating(monkeypatch, capsys) -> None:
    _, create_calls = _install_roster_run(monkeypatch)
    _stub_creation_plan(monkeypatch)

    result = acl_tool.main(["config.yml", "--dry-run", "--create-and-email-users"])

    out = capsys.readouterr().out
    assert result == 0
    assert create_calls == []
    assert "!! CREATE AND EMAIL: 3 account(s) would be created" in out
    assert "- lead@example.com -> user lead, roles leads_public" in out
    assert "- alice@example.com -> user alice, roles Analysts" in out
    assert "- bob@example.com -> user bob, roles Analysts" in out
    assert "cannot be recalled" in out


def test_acl_tool_dry_run_names_the_accounts_it_would_create(
    monkeypatch, capsys
) -> None:
    """The real dry run of an ordinary roster: every address named, none created.

    Unstubbed, so the derivation the real plan performs is what gets printed. The
    addresses are shown in full rather than counted because the welcome mail is
    sent by the creation itself, making the dry run the last point at which the
    roster can still be corrected.
    """
    _, create_calls = _install_roster_run(monkeypatch)

    result = acl_tool.main(["config.yml", "--dry-run", "--create-and-email-users"])

    out = capsys.readouterr().out
    assert result == 0
    assert create_calls == []
    assert "!! CREATE AND EMAIL: 3 account(s) would be created" in out
    assert "- alice@example.com -> user alice_example_com, roles Analysts" in out
    assert "- lead@example.com -> user lead_example_com, roles leads_public" in out
    assert "cannot be recalled" in out
    assert "cannot be created" not in out


def test_acl_tool_creates_the_handles_the_plan_derived(monkeypatch, capsys) -> None:
    """End to end with nothing stubbed: derived handle reaches users.create.

    The other creation tests hand the CLI a plan so they can isolate the prompt,
    the cap and the failure path; this one lets the real plan run, so the name
    the registry is asked for is the one `derive_username` produced.
    """
    _, create_calls = _install_roster_run(monkeypatch)

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    assert result == 0
    assert [args for args, _kwargs in create_calls] == [
        ("lead_example_com", "lead@example.com", "leads_public"),
        ("alice_example_com", "alice@example.com", "Analysts"),
        ("bob_example_com", "bob@example.com", "Analysts"),
    ]
    assert (
        "+ user alice_example_com (role Analysts, emailed)" in capsys.readouterr().out
    )


def test_acl_tool_creates_roster_users_with_yes(monkeypatch, capsys) -> None:
    _, create_calls = _install_roster_run(monkeypatch)
    _stub_creation_plan(monkeypatch)
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: pytest.fail("--yes must not prompt"),
    )

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    out = capsys.readouterr().out
    assert result == 0
    assert [args for args, _kwargs in create_calls] == [
        ("lead", "lead@example.com", "leads_public"),
        ("alice", "alice@example.com", "Analysts"),
        ("bob", "bob@example.com", "Analysts"),
    ]
    assert "!! CREATE AND EMAIL: 3 account(s) will be created" in out
    assert "+ user alice (role Analysts, emailed)" in out


def test_acl_tool_refuses_colliding_addresses_and_exits_one(
    monkeypatch, capsys
) -> None:
    """Nothing creatable means the registry is never contacted, and exit is 1.

    Both addresses fold to one handle, so neither can be created. The run reports
    each address it could not onboard and sends no mail, rather than issuing a
    creation and letting the registry reject the second one after the first has
    already been mailed.
    """

    def _never(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("the registry must not be contacted")

    colliding = acl.parse_acl_config_text("""
policies:
  public:
    sso.groups: [Everyone]
    buckets.read: [bucket-a]
    config.default_role: true
roles:
  Analysts:
    sso.email: [a.b@example.com, a+b@example.com]
    config.policies: [public]
""")
    _, create_calls = _install_roster_run(monkeypatch, create=_never, config=colliding)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "create_roster_users",
        lambda *_args, **_kwargs: pytest.fail(
            "create_roster_users must not be reached"
        ),
    )

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    captured = capsys.readouterr()
    assert result == 1
    assert create_calls == []
    assert (
        "No accounts to create: 0 roster address(es) already have one and 2 "
        "cannot be created." in captured.out
    )
    assert (
        "Warning: Roster address 'a.b@example.com' derives username "
        "'a_b_example_com', which is also derived by 'a+b@example.com'"
    ) in captured.err
    assert "Done with 2 warning(s)." in captured.err


def test_acl_tool_declining_the_prompt_creates_nobody(monkeypatch, capsys) -> None:
    _, create_calls = _install_roster_run(monkeypatch)
    _stub_creation_plan(monkeypatch)
    prompts: list[str] = []

    def _decline(prompt: str) -> str:
        prompts.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", _decline)

    result = acl_tool.main(["config.yml", "--create-and-email-users"])

    captured = capsys.readouterr()
    assert result == 1
    assert create_calls == []
    assert prompts == ["Create and email 3 account(s)? [y/N]: "]
    assert "!! CREATE AND EMAIL: 3 account(s) will be created" in captured.out
    assert "- alice@example.com" in captured.out
    assert "3 roster account(s) were not created (user declined)." in captured.err


def test_acl_tool_refuses_more_creations_than_the_cap(monkeypatch, capsys) -> None:
    _, create_calls = _install_roster_run(monkeypatch)
    _stub_creation_plan(monkeypatch)

    result = acl_tool.main(
        ["config.yml", "--yes", "--create-and-email-users", "--max-created-users", "2"]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert create_calls == []
    assert (
        "!! REFUSED: Refusing to create and email 3 account(s): more than "
        "--max-created-users (2). Re-run with --max-created-users 3" in captured.err
    )


def test_acl_tool_creation_failure_becomes_a_warning_and_exits_one(
    monkeypatch, capsys
) -> None:
    def _fail(name: str, *_args: Any, **_kwargs: Any) -> None:
        if name == "alice":
            raise RuntimeError("EmailAlreadyInUse")

    _, create_calls = _install_roster_run(monkeypatch, create=_fail)
    _stub_creation_plan(monkeypatch)

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    captured = capsys.readouterr()
    assert result == 1
    assert len(create_calls) == 3
    assert (
        "Warning: User 'alice@example.com' could not be created: EmailAlreadyInUse"
        in captured.err
    )
    assert "Done with 1 warning(s)." in captured.err


def test_acl_tool_reports_when_every_roster_address_has_an_account(
    monkeypatch, capsys
) -> None:
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "lead@example.com", "leads_public")
    _add_user(current, "alice@example.com", "Analysts")
    _add_user(current, "bob@example.com", "Analysts")
    _, create_calls = _install_roster_run(monkeypatch, current=current)

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    out = capsys.readouterr().out
    assert result == 0
    assert create_calls == []
    assert "No accounts to create: 3 roster address(es) already have one." in out


def test_acl_tool_ambiguous_held_address_is_reported_without_failing(
    monkeypatch, capsys
) -> None:
    """A held address is counted once, and holding it twice is not a failure.

    Two accounts answering for one roster address needs no action and is already
    in `existing`, so counting it as uncreatable both named it twice and turned a
    run with nothing to do into an exit-1.
    """
    config = _roster_config()
    current = _current_state_for_config(config)
    _add_user(current, "lead@example.com", "leads_public")
    _add_user(current, "bob@example.com", "Analysts")
    _add_user(current, "alice", "Analysts", email="alice@example.com")
    _add_user(current, "alice_two", "Analysts", email="alice@example.com")
    _, create_calls = _install_roster_run(monkeypatch, current=current)

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    captured = capsys.readouterr()
    assert result == 0
    assert create_calls == []
    assert "No accounts to create: 3 roster address(es) already have one." in (
        captured.out
    )
    assert captured.out.count("already have one") == 1
    assert "cannot be created" not in captured.out
    assert (
        "! Roster address 'alice@example.com' is the email of 'alice', 'alice_two'"
        in captured.out
    )
    assert "Warning:" not in captured.err


def test_acl_tool_create_and_email_users_requires_a_config_file(capsys) -> None:
    with pytest.raises(SystemExit):
        acl_tool.main(["--create-and-email-users"])

    assert "--create-and-email-users requires a config_file" in capsys.readouterr().err


def test_acl_tool_max_created_users_requires_the_creation_flag(capsys) -> None:
    with pytest.raises(SystemExit):
        acl_tool.main(["config.yml", "--max-created-users", "50"])

    err = capsys.readouterr().err
    assert "--max-created-users requires --create-and-email-users" in err


def test_acl_tool_max_created_users_at_the_default_still_requires_the_flag(
    capsys,
) -> None:
    """Presence of the flag is what is tested, not whether its value differs."""
    with pytest.raises(SystemExit):
        acl_tool.main(
            [
                "config.yml",
                "--max-created-users",
                str(acl_tool.MAX_CREATED_USERS_DEFAULT),
            ]
        )

    err = capsys.readouterr().err
    assert "--max-created-users requires --create-and-email-users" in err


def test_acl_tool_creates_users_after_roles_and_drift_reset(monkeypatch) -> None:
    """Creation is rejected for a role that does not exist yet, so it runs last."""
    calls: list[str] = []
    config = _roster_config()
    current = _empty_current_state()
    stack = _fake_stack(
        users=SimpleNamespace(create=lambda *args, **kwargs: calls.append("create"))
    )
    _install_acl_tool_stack(monkeypatch, stack)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: config)

    states = [current, _current_state_for_config(config)]
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "fetch_current_state",
        lambda _stack: states.pop(0) if states else _current_state_for_config(config),
    )

    def _apply_acl(*_args: Any, **_kwargs: Any) -> list[str]:
        calls.append("apply_acl")
        return []

    def _handle_drift(*_args: Any, **_kwargs: Any) -> tuple[list[str], Any]:
        calls.append("drift")
        return [], _current_state_for_config(config)

    monkeypatch.setattr(acl_tool.acl_lib, "apply_acl", _apply_acl)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "detect_policy_drift",
        lambda _desired, _current: [
            acl.PolicyDrift(title="public", desired=[], actual=[])
        ],
    )
    monkeypatch.setattr(acl_tool, "_handle_policy_drift", _handle_drift)
    _stub_creation_plan(monkeypatch)

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    assert result == 0
    assert calls == ["apply_acl", "drift", "create", "create", "create"]


def test_acl_tool_reports_username_collision_and_exits_one(monkeypatch, capsys) -> None:
    """A collision creates nobody for that address and is not silent."""
    long_address = ("l" * 70) + "@example.com"
    config = acl.parse_acl_config_text(f"""
policies:
  public:
    sso.email: [{long_address}]
    buckets.read: [bucket-a]
    config.default_role: true
roles: {{}}
""")
    current = _current_state_for_config(config)
    _add_user(current, long_address[:64], "public", email="squatter@example.com")
    create_calls: list[Any] = []
    stack = _fake_stack(
        users=SimpleNamespace(
            create=lambda *args, **kwargs: create_calls.append((args, kwargs))
        )
    )
    _install_acl_tool_stack(monkeypatch, stack)
    monkeypatch.setattr(acl_tool.acl_lib, "parse_acl_config", lambda _path: config)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)

    result = acl_tool.main(["config.yml", "--yes", "--create-and-email-users"])

    captured = capsys.readouterr()
    assert result == 1
    assert create_calls == []
    assert (
        "No accounts to create: 0 roster address(es) already have one and 1 "
        "cannot be created." in captured.out
    )
    assert f"Warning: Roster address '{long_address}' derives username" in captured.err
    assert "Done with 1 warning(s)." in captured.err
