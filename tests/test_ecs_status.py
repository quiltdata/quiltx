"""Tests for the ECS status tool."""

from __future__ import annotations

from quiltx.tools.ecs import status as status_tool
from tests.conftest import make_fake_catalog


class _StableEcsClient:
    def describe_services(self, *, cluster: str, services: list[str]):
        return {
            "services": [
                {
                    "desiredCount": 1,
                    "runningCount": 1,
                    "pendingCount": 0,
                    "taskDefinition": "task-def:1",
                    "deployments": [
                        {
                            "status": "PRIMARY",
                            "rolloutState": "COMPLETED",
                            "desiredCount": 1,
                            "runningCount": 1,
                            "pendingCount": 0,
                        }
                    ],
                    "events": [{"message": "steady state"}],
                }
            ]
        }


def test_status_explicit_target_with_region_skips_stack_payload(monkeypatch) -> None:
    calls = {}
    fake = make_fake_catalog("example.com")

    monkeypatch.setattr(
        status_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **_kw: fake,
    )

    def _ensure_stack_payload(*_args, **_kwargs):
        raise AssertionError("status should not discover stack with explicit target")

    monkeypatch.setattr(
        status_tool.stack_lib,
        "ensure_stack_payload",
        _ensure_stack_payload,
    )

    def _aws_client(service_name, payload=None, *, region=None):
        calls["service_name"] = service_name
        calls["payload"] = payload
        calls["region"] = region
        return _StableEcsClient()

    monkeypatch.setattr(status_tool.stack_lib, "aws_client", _aws_client)

    rc = status_tool.main(
        [
            "--catalog",
            "example.com",
            "--cluster",
            "cluster",
            "--service",
            "service",
            "--region",
            "us-east-1",
        ]
    )

    assert rc == 0
    assert calls == {
        "service_name": "ecs",
        "payload": None,
        "region": "us-east-1",
    }
