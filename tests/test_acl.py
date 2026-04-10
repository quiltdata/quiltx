"""Tests for declarative stack ACL reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

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
    permissions: list
    roles: list


@dataclass
class FakeRole:
    id: str
    name: str
    policies: list
    permissions: list
    typename__: str = "ManagedRole"


@dataclass
class FakeBucket:
    name: str
    title: str


def test_parse_acl_config_valid(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
bucket_policies:
  public:
    read: [bucket-a]
  internal:
    read_write: [bucket-b]
roles:
  visitor:
    bucket_policies: [public]
    default: true
sso:
  - match:
      groups: Everyone
    roles: [visitor]
    admin: true
""")

    config = acl.parse_acl_config(config_path)
    assert sorted(config.bucket_policies) == ["internal", "public"]
    assert config.roles["visitor"].bucket_policies == ["public"]
    assert config.roles["visitor"].default is True
    assert config.default_role_name == "visitor"
    assert config.sso[0].match == {"groups": "Everyone"}
    assert config.sso[0].admin is True


def test_parse_acl_config_rejects_multiple_default_roles(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
bucket_policies:
  public:
    read: [bucket-a]
roles:
  visitor:
    bucket_policies: [public]
    default: true
  member:
    bucket_policies: [public]
    default: true
""")

    with pytest.raises(ValueError, match="Only one role may set default: true"):
        acl.parse_acl_config(config_path)


def test_parse_acl_config_rejects_unknown_role_reference(tmp_path: Path) -> None:
    config_path = tmp_path / "acl.yml"
    config_path.write_text("""
bucket_policies: {}
roles: {}
sso:
  - match:
      groups: Everyone
    roles: [visitor]
""")

    try:
        acl.parse_acl_config(config_path)
    except ValueError as exc:
        assert "unknown roles" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Expected ValueError")


def test_build_sso_config_omits_default_role() -> None:
    text = acl.build_sso_config(
        [
            acl.AclSsoMapping(
                match={"groups": "Employees"}, roles=["member"], admin=True
            ),
            acl.AclSsoMapping(match={"email": "[email protected]"}, roles=["admin"]),
        ]
    )

    payload = yaml.safe_load(text)
    assert payload["version"] == "1.0"
    assert "default_role" not in payload
    assert (
        payload["mappings"][0]["schema"]["properties"]["groups"]["contains"]["const"]
        == "Employees"
    )
    assert (
        payload["mappings"][1]["schema"]["properties"]["email"]["const"]
        == "[email protected]"
    )


def test_compute_diff_handles_updates_deletes_and_unmanaged_collisions() -> None:
    desired = acl.AclConfig(
        bucket_policies={
            "public": acl.AclBucketPolicy(name="public", read=["bucket-a"]),
            "internal": acl.AclBucketPolicy(name="internal", read_write=["bucket-b"]),
            "external": acl.AclBucketPolicy(name="external", read=["bucket-z"]),
        },
        roles={
            "visitor": acl.AclRole(
                name="visitor", bucket_policies=["public", "internal"], default=True
            ),
            "member": acl.AclRole(name="member", bucket_policies=["public"]),
        },
        sso=[acl.AclSsoMapping(match={"groups": "Everyone"}, roles=["visitor"])],
        default_role_name="visitor",
    )

    current = acl.CurrentState(
        buckets={"bucket-a": FakeBucket("bucket-a", "bucket-a")},
        managed_policies={
            "public": FakePolicy(
                id="policy-public",
                title="public",
                managed=True,
                permissions=[acl.Permission.read("bucket-a")],
                roles=[],
            ),
            "legacy": FakePolicy(
                id="policy-legacy",
                title="legacy",
                managed=True,
                permissions=[acl.Permission.read("bucket-old")],
                roles=[],
            ),
        },
        unmanaged_policies={
            "external": FakePolicy(
                id="policy-external",
                title="external",
                managed=False,
                permissions=[acl.Permission.read("bucket-z")],
                roles=[],
            )
        },
        all_policies={},
        managed_roles={
            "visitor": FakeRole(
                id="role-visitor",
                name="visitor",
                policies=[FakePolicySummary(id="policy-public", title="public")],
                permissions=[],
            ),
            "legacy": FakeRole(
                id="role-legacy",
                name="legacy",
                policies=[FakePolicySummary(id="policy-legacy", title="legacy")],
                permissions=[],
            ),
            "protected": FakeRole(
                id="role-protected",
                name="protected",
                policies=[],
                permissions=[],
            ),
        },
        unmanaged_roles={
            "member": FakeRole(
                id="role-member",
                name="member",
                policies=[],
                permissions=[],
                typename__="UnmanagedRole",
            )
        },
        all_roles={},
        sso_config_text="""
version: "1.0"
mappings:
  - schema:
      type: object
      properties:
        groups:
          type: array
          contains:
            const: Legacy
      required: [groups]
    roles: [protected]
    admin: false
""",
        default_role_name="legacy",
    )
    current.all_policies.update(current.unmanaged_policies)
    current.all_policies.update(current.managed_policies)
    current.all_roles.update(current.unmanaged_roles)
    current.all_roles.update(current.managed_roles)

    diff = acl.compute_diff(desired, current)

    assert diff.buckets_to_add == ["bucket-b", "bucket-z"]
    assert [policy.title for policy in diff.policies_to_create] == ["internal"]
    assert diff.policies_to_delete == ["legacy"]
    assert [role.name for role in diff.roles_to_update] == ["visitor"]
    assert diff.roles_to_create == []
    assert diff.roles_to_delete == []
    assert diff.default_role_name == "visitor"
    assert diff.default_role_needs_update is True
    assert diff.sso_needs_update is True
    assert diff.sso_is_create is False
    assert any("unmanaged" in warning for warning in diff.warnings)
    assert any("protected" in warning for warning in diff.warnings)
    assert any("current default role" in warning for warning in diff.warnings)


def test_compute_diff_sso_create_when_no_existing_config() -> None:
    desired = acl.AclConfig(
        bucket_policies={
            "public": acl.AclBucketPolicy(name="public", read=["bucket-a"]),
        },
        roles={
            "visitor": acl.AclRole(
                name="visitor", bucket_policies=["public"], default=True
            ),
        },
        sso=[acl.AclSsoMapping(match={"groups": "Everyone"}, roles=["visitor"])],
        default_role_name="visitor",
    )
    current = acl.CurrentState(
        buckets={"bucket-a": FakeBucket("bucket-a", "bucket-a")},
        managed_policies={
            "public": FakePolicy(
                id="policy-public",
                title="public",
                managed=True,
                permissions=[acl.Permission.read("bucket-a")],
                roles=[],
            ),
        },
        unmanaged_policies={},
        all_policies={},
        managed_roles={
            "visitor": FakeRole(
                id="role-visitor",
                name="visitor",
                policies=[FakePolicySummary(id="policy-public", title="public")],
                permissions=[],
            ),
        },
        unmanaged_roles={},
        all_roles={},
        sso_config_text=None,
        default_role_name=None,
    )

    diff = acl.compute_diff(desired, current)
    assert diff.sso_needs_update is True
    assert diff.sso_is_create is True
    assert diff.default_role_needs_update is True


def test_with_default_role_returns_updated_copy() -> None:
    config = acl.AclConfig(bucket_policies={}, roles={}, sso=[])
    updated = acl.with_default_role(config, "visitor")
    assert updated.default_role_name == "visitor"
    assert config.default_role_name is None


def test_print_diff_sso_create_vs_update(capsys) -> None:
    create_diff = acl.AclDiff(
        sso_config_text="test", sso_is_create=True, sso_needs_update=True
    )
    acl.print_diff(create_diff)
    assert "+ sso config" in capsys.readouterr().out

    update_diff = acl.AclDiff(
        sso_config_text="test", sso_is_create=False, sso_needs_update=True
    )
    acl.print_diff(update_diff)
    assert "~ sso config" in capsys.readouterr().out


def test_print_diff_shows_default_role(capsys) -> None:
    acl.print_diff(
        acl.AclDiff(default_role_name="visitor", default_role_needs_update=True)
    )
    assert "~ default role visitor" in capsys.readouterr().out


def test_compute_diff_does_not_remove_existing_sso_when_desired_is_empty() -> None:
    desired = acl.AclConfig(bucket_policies={}, roles={}, sso=[])
    current = acl.CurrentState(
        buckets={},
        managed_policies={},
        unmanaged_policies={},
        all_policies={},
        managed_roles={},
        unmanaged_roles={},
        all_roles={},
        sso_config_text='version: "1.0"\nmappings: []\n',
        default_role_name=None,
    )

    diff = acl.compute_diff(desired, current)
    assert diff.sso_needs_update is False


def test_apply_acl_orders_operations_and_continues_after_bucket_warning(
    monkeypatch,
) -> None:
    calls: list[tuple] = []

    def bucket_add(name: str, title: str):
        calls.append(("bucket_add", name, title))
        if name == "bucket-bad":
            raise RuntimeError("missing bucket")
        return FakeBucket(name=name, title=title)

    def policy_create(title: str, *, permissions):
        calls.append(
            ("policy_create", title, [permission.bucket for permission in permissions])
        )
        return FakePolicy(
            id=f"id-{title}",
            title=title,
            managed=True,
            permissions=permissions,
            roles=[],
        )

    def policy_update(id_or_title: str, *, title: str, permissions, roles):
        calls.append(("policy_update", id_or_title, title, roles))
        return FakePolicy(
            id=f"id-{title}",
            title=title,
            managed=True,
            permissions=permissions,
            roles=[],
        )

    def role_create(name: str, policies):
        calls.append(("role_create", name, list(policies)))
        return FakeRole(id=f"id-{name}", name=name, policies=[], permissions=[])

    def role_update(id_or_name: str, *, name: str, policies):
        calls.append(("role_update", id_or_name, name, list(policies)))
        return FakeRole(id=f"id-{name}", name=name, policies=[], permissions=[])

    def sso_set(text: str):
        calls.append(("sso_set", yaml.safe_load(text)))
        return SimpleNamespace(text=text)

    monkeypatch.setattr(acl, "admin_buckets", SimpleNamespace(add=bucket_add))
    monkeypatch.setattr(
        acl,
        "admin_policies",
        SimpleNamespace(
            create_managed=policy_create,
            update_managed=policy_update,
            delete=lambda title: calls.append(("policy_delete", title)),
        ),
    )
    monkeypatch.setattr(
        acl,
        "admin_roles",
        SimpleNamespace(
            create_managed=role_create,
            update_managed=role_update,
            set_default=lambda name: calls.append(("set_default", name)),
            delete=lambda name: calls.append(("role_delete", name)),
        ),
    )
    monkeypatch.setattr(acl, "admin_sso_config", SimpleNamespace(set=sso_set))

    diff = acl.AclDiff(
        buckets_to_add=["bucket-good", "bucket-bad"],
        policies_to_create=[
            acl.PolicyUpdate(
                title="new-policy", permissions=[acl.Permission.read("bucket-good")]
            )
        ],
        policies_to_update=[
            acl.PolicyUpdate(
                title="old-policy",
                permissions=[acl.Permission.read_write("bucket-good")],
            )
        ],
        policies_to_delete=["gone-policy"],
        roles_to_create=[acl.RoleUpdate(name="new-role", policy_titles=["new-policy"])],
        roles_to_update=[
            acl.RoleUpdate(name="old-role", policy_titles=["existing-policy"])
        ],
        roles_to_delete=["gone-role"],
        default_role_name="new-role",
        default_role_needs_update=True,
        sso_config_text=acl.build_sso_config(
            [acl.AclSsoMapping(match={"groups": "Everyone"}, roles=["new-role"])]
        ),
        sso_needs_update=True,
    )
    current = acl.CurrentState(
        buckets={},
        managed_policies={
            "old-policy": FakePolicy("id-old-policy", "old-policy", True, [], [])
        },
        unmanaged_policies={},
        all_policies={
            "existing-policy": FakePolicy(
                "id-existing-policy", "existing-policy", True, [], []
            )
        },
        managed_roles={},
        unmanaged_roles={},
        all_roles={},
        sso_config_text=None,
        default_role_name=None,
    )

    warnings = acl.apply_acl(diff, current)

    assert calls == [
        ("bucket_add", "bucket-good", "bucket-good"),
        ("bucket_add", "bucket-bad", "bucket-bad"),
        ("policy_create", "new-policy", ["bucket-good"]),
        ("policy_update", "old-policy", "old-policy", []),
        ("role_create", "new-role", ["id-new-policy"]),
        ("role_update", "old-role", "old-role", ["id-existing-policy"]),
        ("set_default", "new-role"),
        (
            "sso_set",
            {
                "version": "1.0",
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
                        "roles": ["new-role"],
                        "admin": False,
                    }
                ],
            },
        ),
        ("role_delete", "gone-role"),
        ("policy_delete", "gone-policy"),
    ]
    assert any("bucket-bad" in warning for warning in warnings)


def test_acl_tool_dry_run_does_not_apply(monkeypatch, capsys) -> None:
    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    current = acl.CurrentState(
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

    monkeypatch.setattr(
        acl_tool.acl_lib, "parse_acl_config", lambda path: SimpleNamespace(path=path)
    )
    monkeypatch.setattr(
        acl_tool, "_resolve_default_role_name", lambda config, prompt_for_choice: None
    )
    monkeypatch.setattr(
        acl_tool.acl_lib, "with_default_role", lambda config, name: config
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda: current)
    monkeypatch.setattr(acl_tool.acl_lib, "compute_diff", lambda desired, state: diff)
    monkeypatch.setattr(
        acl_tool.acl_lib,
        "apply_acl",
        lambda *_: (_ for _ in ()).throw(
            AssertionError("apply_acl should not be called")
        ),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt: (_ for _ in ()).throw(
            AssertionError("input should not be called")
        ),
    )

    result = acl_tool.main(["config.yml", "--dry-run"])
    assert result == 0
    captured = capsys.readouterr()
    assert "+ bucket bucket-a" in captured.out
    assert "Applying" not in captured.out


def test_print_diff_verbose(capsys) -> None:
    desired = acl.AclConfig(
        bucket_policies={
            "my-policy": acl.AclBucketPolicy(name="my-policy", read=["bucket-a"])
        },
        roles={
            "my-role": acl.AclRole(
                name="my-role", bucket_policies=["my-policy"], default=True
            )
        },
        sso=[acl.AclSsoMapping(match={"groups": "Everyone"}, roles=["my-role"])],
        default_role_name="my-role",
    )
    diff = acl.AclDiff(
        policies_to_create=[
            acl.PolicyUpdate(
                title="my-policy",
                permissions=[acl.Permission.read("bucket-a")],
            )
        ],
        roles_to_create=[
            acl.RoleUpdate(name="my-role", policy_titles=["my-policy"]),
        ],
        sso_config_text="version: '1.0'\nmappings: []\n",
        sso_is_create=True,
        sso_needs_update=True,
    )
    acl.print_diff(diff, verbose=True, desired=desired)
    out = capsys.readouterr().out
    assert "Desired ACL:" in out
    assert "bucket-a" in out
    assert "policies: my-policy" in out
    assert "default role my-role" in out
    assert "version:" in out


def test_print_diff_verbose_shows_unchanged_entries(capsys) -> None:
    desired = acl.AclConfig(
        bucket_policies={
            "public": acl.AclBucketPolicy(name="public", read=["bucket-a"])
        },
        roles={"visitor": acl.AclRole(name="visitor", bucket_policies=["public"])},
        sso=[],
        default_role_name="visitor",
    )
    current = acl.CurrentState(
        buckets={"bucket-a": FakeBucket("bucket-a", "bucket-a")},
        managed_policies={
            "public": FakePolicy(
                id="policy-public",
                title="public",
                managed=True,
                permissions=[acl.Permission.read("bucket-a")],
                roles=[],
            )
        },
        unmanaged_policies={},
        all_policies={},
        managed_roles={
            "visitor": FakeRole(
                id="role-visitor",
                name="visitor",
                policies=[FakePolicySummary(id="policy-public", title="public")],
                permissions=[],
            )
        },
        unmanaged_roles={},
        all_roles={},
        sso_config_text=None,
        default_role_name="visitor",
    )
    diff = acl.compute_diff(desired, current)

    acl.print_diff(diff, verbose=True, desired=desired, current=current)
    out = capsys.readouterr().out
    assert "= bucket bucket-a" in out
    assert "= policy public" in out
    assert "= role visitor" in out
    assert "= default role visitor" in out


def test_acl_tool_missing_file(capsys) -> None:
    result = acl_tool.main(["/tmp/does-not-exist.yml"])
    assert result == 1

    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_acl_tool_yes_flag_applies_without_prompt(monkeypatch) -> None:
    applied: list[str] = []
    diff = acl.AclDiff(buckets_to_add=["bucket-a"])
    current = acl.CurrentState(
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

    monkeypatch.setattr(
        acl_tool.acl_lib, "parse_acl_config", lambda path: SimpleNamespace(path=path)
    )
    monkeypatch.setattr(
        acl_tool,
        "_resolve_default_role_name",
        lambda config, prompt_for_choice: "visitor",
    )
    monkeypatch.setattr(
        acl_tool.acl_lib, "with_default_role", lambda config, name: config
    )
    monkeypatch.setattr(acl_tool.acl_lib, "fetch_current_state", lambda: current)
    monkeypatch.setattr(acl_tool.acl_lib, "compute_diff", lambda desired, state: diff)
    monkeypatch.setattr(acl_tool.acl_lib, "print_diff", lambda computed, **kw: None)

    def _apply_acl(computed, state):
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


def test_resolve_default_role_name_prefers_declared_default() -> None:
    config = acl.AclConfig(
        bucket_policies={},
        roles={
            "visitor": acl.AclRole(name="visitor", bucket_policies=[], default=True),
            "member": acl.AclRole(name="member", bucket_policies=[]),
        },
        sso=[],
        default_role_name="visitor",
    )
    assert (
        acl_tool._resolve_default_role_name(config, prompt_for_choice=True) == "visitor"
    )


def test_resolve_default_role_name_prompts_by_number(monkeypatch, capsys) -> None:
    monkeypatch.setattr(acl_tool.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "2")
    config = acl.AclConfig(
        bucket_policies={},
        roles={
            "visitor": acl.AclRole(name="visitor", bucket_policies=[]),
            "member": acl.AclRole(name="member", bucket_policies=[]),
        },
        sso=[],
    )

    selected = acl_tool._resolve_default_role_name(config, prompt_for_choice=True)
    assert selected == "member"
    out = capsys.readouterr().out
    assert "1. visitor" in out
    assert "2. member" in out


def test_resolve_default_role_name_defaults_to_first_without_prompt() -> None:
    config = acl.AclConfig(
        bucket_policies={},
        roles={
            "visitor": acl.AclRole(name="visitor", bucket_policies=[]),
            "member": acl.AclRole(name="member", bucket_policies=[]),
        },
        sso=[],
    )
    assert (
        acl_tool._resolve_default_role_name(config, prompt_for_choice=False)
        == "visitor"
    )


def test_resolve_default_role_name_defaults_to_first_when_stdin_not_tty(
    monkeypatch,
) -> None:
    monkeypatch.setattr(acl_tool.sys.stdin, "isatty", lambda: False)
    config = acl.AclConfig(
        bucket_policies={},
        roles={
            "visitor": acl.AclRole(name="visitor", bucket_policies=[]),
            "member": acl.AclRole(name="member", bucket_policies=[]),
        },
        sso=[],
    )
    assert (
        acl_tool._resolve_default_role_name(config, prompt_for_choice=True) == "visitor"
    )
