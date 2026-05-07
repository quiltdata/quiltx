"""Tests for declarative stack ACL reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

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
    assert "belong under top-level 'roles:'" in policy_message

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


def test_parse_acl_config_accepts_arbitrary_sso_claims(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
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
  internal:
    sso.groups: [Employees]
  exec:
    sso.users: [ernest@quilt.bio]
roles: {}
""")

    config = acl.parse_acl_config(config_path)

    assert config.policies[2].sso == {"users": ["ernest@quilt.bio"]}


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


def test_parse_acl_config_rejects_multiple_default_policies(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
    config.default_role: true
  internal:
    sso.groups: [Everyone]
    config.default_role: true
roles: {}
""")

    with pytest.raises(ValueError, match="Only one policy may set config.default_role"):
        acl.parse_acl_config(config_path)


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


def test_policy_config_is_admin_marks_synthesized_role_admin(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
policies:
  public:
    sso.groups: [Everyone]
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
                name="public", sso={"groups": ["Everyone"]}, read=["bucket-a"]
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
                name="internal", sso={"groups": ["Everyone"]}, read=["bucket-b"]
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


def test_changing_policy_groups_updates_sso_config() -> None:
    original = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public", sso={"groups": ["Everyone"]}, read=["bucket-a"]
            )
        ],
        roles={},
    )
    updated = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public", sso={"groups": ["Employees"]}, read=["bucket-a"]
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

    acl.print_current_state(current)
    out = capsys.readouterr().out

    assert "policy public (managed)" in out
    assert "role internal_public (default) (managed)" in out
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

    def role_create(name: str, policies: list[str]) -> FakeRole:
        calls.append(("role_create", name, list(policies)))
        return FakeRole(id=f"id-{name}", name=name, policies=[], permissions=[])

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

    acl.apply_acl(stack, diff, current)

    assert calls == [
        ("bucket_add", "bucket-a", "bucket-a"),
        ("policy_create", "public"),
        ("role_create", "public", ["id-public"]),
        ("sso_set", "public"),
        ("role_delete", "legacy_role"),
        ("policy_delete", "legacy_policy"),
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
        sso_config_text="version: '1.0'\nmappings: []\n",
    )

    warnings = acl.apply_acl(stack, diff, _empty_current_state())

    assert warnings == []
    assert calls == [
        ("sso_set", None),
        ("remove_roles", "alice", ["legacy_role"], "default"),
        ("role_delete", "legacy_role"),
        ("sso_set", "version: '1.0'\nmappings: []\n"),
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


def test_apply_acl_falls_back_to_policy_update_when_role_detach_fails() -> None:
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


def test_acl_tool_no_config_shows_current_state(monkeypatch, capsys) -> None:
    current = _empty_current_state()
    current.buckets["bucket-a"] = FakeBucket(name="bucket-a", title="bucket-a")
    _install_acl_tool_stack(monkeypatch)
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda _stack: current)

    result = acl_tool.main([])

    assert result == 0
    assert "bucket bucket-a" in capsys.readouterr().out


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
