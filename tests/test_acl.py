"""Tests for declarative stack ACL reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from quiltx import acl
from quiltx.tools.stack import acl as acl_tool


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
    assert config.policies[0].groups == ["Everyone"]
    assert config.roles == {}


def test_parse_acl_config_accepts_simpler_stack_acl_example() -> None:
    config = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))

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
        policies=[acl.AclPolicy(name="public", groups=["Everyone"], read=["bucket-a"])],
        roles={
            "exec": acl.AclStaticRole(
                name="exec",
                groups=["Executives"],
                read=["bucket-b"],
                read_write=["bucket-c"],
            )
        },
    )

    assert acl.all_buckets(config) == {"bucket-a", "bucket-b", "bucket-c"}


def test_build_sso_config_emits_policy_and_static_role_mappings() -> None:
    config = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))

    sso_config = acl.build_sso_config(config)
    assert sso_config is not None
    payload = yaml.safe_load(sso_config)

    assert payload["default_role"] == "public"
    assert payload["mappings"][0]["roles"] == ["public"]
    assert payload["mappings"][1]["roles"] == ["internal_public"]
    assert payload["mappings"][2]["roles"] == ["exec"]
    assert payload["mappings"][2]["admin"] is True


def test_compute_diff_from_simpler_stack_acl_example_against_empty_state() -> None:
    desired = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
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
    desired = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
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
                name="public", groups=["Everyone"], read=["bucket-a"], default_role=True
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
            acl.AclPolicy(name="public", groups=["Everyone"], read=["bucket-a"]),
            acl.AclPolicy(name="internal", groups=["Everyone"], read=["bucket-b"]),
        ],
        roles={},
    )
    second = acl.AclConfig(
        policies=[
            acl.AclPolicy(name="internal", groups=["Everyone"], read=["bucket-b"]),
            acl.AclPolicy(name="public", groups=["Everyone"], read=["bucket-a"]),
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
    desired = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))

    diff = acl.compute_diff(desired, _empty_current_state())

    exec_role = next(role for role in diff.roles_to_create if role.name == "exec")
    assert exec_role.policy_titles == ["public", "internal", "exec__inline"]
    assert any(policy.title == "exec__inline" for policy in diff.policies_to_create)


def test_compute_diff_is_idempotent_against_matching_current_state() -> None:
    desired = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
    current = _current_state_for_config(desired)

    diff = acl.compute_diff(desired, current)

    assert diff.has_changes() is False
    assert diff.warnings == []


def test_compute_diff_warns_and_skips_unmanaged_name_collisions() -> None:
    desired = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
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
        policies=[acl.AclPolicy(name="public", groups=["Everyone"], read=["bucket-a"])],
        roles={},
    )
    updated = acl.AclConfig(
        policies=[
            acl.AclPolicy(name="public", groups=["Employees"], read=["bucket-a"])
        ],
        roles={},
    )
    current = _current_state_for_config(original)

    diff = acl.compute_diff(updated, current)

    assert diff.sso_needs_update is True
    assert "Employees" in (diff.sso_config_text or "")


def test_policy_rename_cleans_up_old_synthesized_role_in_single_pass() -> None:
    original = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
    current = _current_state_for_config(original)

    renamed = acl.AclConfig(
        policies=[
            acl.AclPolicy(
                name="public",
                groups=["Everyone"],
                read=["quilt-example"],
                default_role=True,
            ),
            acl.AclPolicy(
                name="employees",
                groups=["Employees"],
                read=["quilt-leadership"],
                read_write=["quilt-bake", "quilt-dev"],
            ),
        ],
        roles={
            "exec": acl.AclStaticRole(
                name="exec",
                groups=["Executives"],
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
    desired = acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
    diff = acl.compute_diff(desired, _empty_current_state())

    acl.print_diff(diff, verbose=True, desired=desired)
    out = capsys.readouterr().out

    assert "role internal_public (synthesized from policies public, internal)" in out
    assert "policy exec__inline (generated inline policy)" in out
    assert "admin: true" in out


def test_print_current_state_summarizes_server_acl(capsys) -> None:
    current = _current_state_for_config(
        acl.parse_acl_config(Path("spec/060-stack-acl/simpler-stack-acl.yml"))
    )

    acl.print_current_state(current)
    out = capsys.readouterr().out

    assert "policy public (managed)" in out
    assert "role internal_public (managed)" in out
    assert "default_role: public" in out
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

    monkeypatch.setattr(acl, "admin_buckets", SimpleNamespace(add=bucket_add))
    # Force the simple (non-cross-account) bucket add path in apply_acl.
    monkeypatch.setattr(
        "quiltx.config.get_catalog_config",
        lambda: (_ for _ in ()).throw(RuntimeError("no config in test")),
    )
    monkeypatch.setattr(
        acl,
        "admin_policies",
        SimpleNamespace(
            create_managed=policy_create,
            update_managed=lambda *args, **kwargs: None,
            delete=lambda title: calls.append(("policy_delete", title)),
        ),
    )
    monkeypatch.setattr(
        acl,
        "admin_roles",
        SimpleNamespace(
            create_managed=role_create,
            update_managed=lambda *args, **kwargs: None,
            delete=lambda name: calls.append(("role_delete", name)),
        ),
    )
    monkeypatch.setattr(acl, "admin_sso_config", SimpleNamespace(set=sso_set))

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
                        groups=["Everyone"],
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

    acl.apply_acl(diff, current)

    assert calls == [
        ("bucket_add", "bucket-a", "bucket-a"),
        ("policy_create", "public"),
        ("role_create", "public", ["id-public"]),
        ("sso_set", "public"),
        ("role_delete", "legacy_role"),
        ("policy_delete", "legacy_policy"),
    ]


def test_apply_acl_uses_cross_account_registration_when_stack_available(
    monkeypatch,
) -> None:
    """When a control account is available, apply_acl goes through the full
    cross-account bucket registration path (including profile retry)."""
    calls: list[tuple[Any, ...]] = []

    def fake_register(
        bucket: str, control_account_id: str, *, assume_yes: bool
    ) -> None:
        calls.append(("register", bucket, control_account_id, assume_yes))

    monkeypatch.setattr(acl, "_register_bucket_with_retry", fake_register)
    monkeypatch.setattr(
        acl, "admin_buckets", SimpleNamespace(add=lambda *a, **kw: None)
    )
    monkeypatch.setattr(
        "quiltx.config.get_catalog_config", lambda: {"navigator_url": "https://x"}
    )
    monkeypatch.setattr("quiltx.stack.extract_catalog_name", lambda _config: "catalog")
    monkeypatch.setattr(
        "quiltx.stack.load_stack_payload", lambda _name: {"account_id": "111"}
    )

    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    acl.apply_acl(diff, _empty_current_state(), assume_yes=True)

    assert calls == [("register", "bucket-a", "111", True)]


def test_acl_tool_dry_run_does_not_apply(monkeypatch, capsys) -> None:
    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    current = _empty_current_state()

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "parse_acl_config",
        lambda path: acl.AclConfig(policies=[], roles={}),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda: current)
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

    monkeypatch.setattr(
        acl_tool.acl_lib,
        "parse_acl_config",
        lambda path: acl.AclConfig(policies=[], roles={}),
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda: current)
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
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda: current)

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
