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
    assert "Explicit roles also support the magic config.policies key" in role_message


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
        sns_topic_arn="arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
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
    assert warnings == ["Bucket 'bad-bucket' could not be added: BucketDoesNotExist"]


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
        unmanaged_roles={},
        all_roles=dict(managed_roles),
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
