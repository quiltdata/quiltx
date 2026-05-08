"""Tests for the logs helpers."""

from __future__ import annotations

import json
from datetime import timezone

import boto3
from botocore.stub import Stubber

from quiltx import logs
from quiltx import stack
from quiltx.tools.ecs import logs as logs_tool
from tests.conftest import make_fake_catalog


def test_parse_time_epoch_seconds() -> None:
    dt = logs.parse_time("1700000000")
    assert dt.tzinfo == timezone.utc
    assert int(dt.timestamp()) == 1700000000


def test_parse_time_epoch_millis() -> None:
    dt = logs.parse_time("1700000000000")
    assert dt.tzinfo == timezone.utc
    assert int(dt.timestamp()) == 1700000000


def test_resolve_time_range_explicit() -> None:
    start_ms, end_ms = logs.resolve_time_range(
        "2024-01-01T00:00:00Z",
        "2024-01-01T01:00:00Z",
        None,
        None,
        None,
    )
    assert end_ms - start_ms == 60 * 60 * 1000


def test_load_stack_payload(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(stack, "user_data_path", lambda *_args, **_kwargs: tmp_path)
    payload_path = tmp_path / "catalog" / "stack.json"
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_text(json.dumps({"region": "us-east-1"}))

    payload = logs.load_stack_payload("catalog")
    assert payload["region"] == "us-east-1"


def test_iter_log_events_with_filter() -> None:
    client = boto3.client(
        "logs",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "filter_log_events",
        {
            "events": [
                {
                    "logStreamName": "stream",
                    "timestamp": 1700000000000,
                    "message": "hello",
                    "ingestionTime": 1700000001000,
                    "eventId": "id",
                }
            ],
            "searchedLogStreams": [],
        },
        {
            "logGroupName": "/aws/lambda/a",
            "startTime": 1,
            "endTime": 2,
            "filterPattern": "ERROR",
        },
    )
    stubber.activate()

    events = list(
        logs.iter_log_events(["/aws/lambda/a"], 1, 2, "ERROR", logs_client=client)
    )
    assert events[0]["message"] == "hello"

    stubber.deactivate()


def test_format_event() -> None:
    event = {
        "timestamp": 1700000000000,
        "logGroupName": "/aws/lambda/a",
        "message": "hello",
    }
    formatted = logs.format_event(event)
    assert "/aws/lambda/a" in formatted
    assert "hello" in formatted


def test_parse_log_level_with_error() -> None:
    level, msg = logs.parse_log_level("ERROR: Connection failed")
    assert level == "ERROR"
    assert msg == "Connection failed"


def test_parse_log_level_with_warning() -> None:
    level, msg = logs.parse_log_level("WARNING: High memory usage")
    assert level == "WARN"
    assert msg == "High memory usage"


def test_parse_log_level_with_warn() -> None:
    level, msg = logs.parse_log_level("WARN: Something happened")
    assert level == "WARN"
    assert msg == "Something happened"


def test_parse_log_level_with_info() -> None:
    level, msg = logs.parse_log_level("INFO: Processing request")
    assert level == "INFO"
    assert msg == "Processing request"


def test_parse_log_level_with_debug() -> None:
    level, msg = logs.parse_log_level("DEBUG: Detailed info")
    assert level == "DEBUG"
    assert msg == "Detailed info"


def test_parse_log_level_with_brackets() -> None:
    level, msg = logs.parse_log_level("[ERROR] Something broke")
    assert level == "ERROR"
    assert msg == "Something broke"


def test_parse_log_level_no_level() -> None:
    level, msg = logs.parse_log_level("Just a plain message")
    assert level == "INFO"
    assert msg == "Just a plain message"


def test_parse_log_level_level_in_middle() -> None:
    level, msg = logs.parse_log_level("Something ERROR happened")
    assert level == "ERROR"
    assert msg == "Something ERROR happened"


def test_format_event_structured() -> None:
    event = {
        "timestamp": 1700000000000,
        "logGroupName": "/aws/lambda/test",
        "logStreamName": "2024/01/01/[1]abc123",
        "message": "ERROR: Something went wrong",
    }
    structured = logs.format_event_structured(event)
    assert structured["level"] == "ERROR"
    assert structured["log_group"] == "/aws/lambda/test"
    assert structured["log_stream"] == "2024/01"  # First two parts (service/component)
    assert "Something went wrong" in structured["message"]
    assert "Nov 14" in structured["timestamp"]  # Human-friendly format


def test_format_event_structured_no_level() -> None:
    event = {
        "timestamp": 1700000000000,
        "logGroupName": "/aws/ecs/service",
        "message": "Processing request 12345",
    }
    structured = logs.format_event_structured(event)
    assert structured["level"] == "INFO"
    assert structured["log_group"] == "/aws/ecs/service"
    assert "Processing request 12345" in structured["message"]


def test_format_event_structured_warning() -> None:
    event = {
        "timestamp": 1700000000000,
        "logGroupName": "/aws/lambda/func",
        "message": "WARNING: Memory usage high",
    }
    structured = logs.format_event_structured(event)
    assert structured["level"] == "WARN"
    assert "Memory usage high" in structured["message"]


def test_logs_auto_discovers_stack_payload_when_cache_missing(
    tmp_path, monkeypatch, capsys
) -> None:
    """quiltx ecs logs should use the shared stack discovery path on cache miss."""
    monkeypatch.setattr(stack, "user_data_path", lambda *_a, **_kw: tmp_path)
    fake = make_fake_catalog("nightly.quilttest.com")
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **_kw: fake,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "fetch_catalog_config",
        lambda _url: {"region": "us-east-1"},
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "fetch_region",
        lambda _catalog, _catalog_config=None: "us-east-1",
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "find_matching_stack",
        lambda _catalog, region=None: {
            "StackName": "quilt",
            "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/quilt/abc",
            "Outputs": [],
            "Parameters": [],
        },
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "list_log_group_resources",
        lambda _catalog, _stack_name, region=None: [
            {"logical_id": "RegistryLogGroup", "log_group_name": "/aws/ecs/registry"}
        ],
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "list_ecs_resources",
        lambda _catalog, _stack_name, region=None: [],
    )

    class _EmptyLogsClient:
        def get_paginator(self, _name):
            class _Paginator:
                def paginate(self, **_kwargs):
                    return [{"events": []}]

            return _Paginator()

    monkeypatch.setattr(
        logs_tool.stack_lib, "aws_client", lambda *_a, **_kw: _EmptyLogsClient()
    )

    rc = logs_tool.main(["--catalog", "nightly.quilttest.com", "--no-follow"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Discovering stack for nightly.quilttest.com" in captured.err
    payload = stack.load_stack_payload("nightly.quilttest.com")
    assert payload is not None
    assert payload["region"] == "us-east-1"


def test_set_level_uses_stack_context(monkeypatch) -> None:
    fake = make_fake_catalog("nightly.quilttest.com")
    payload = {
        "region": "us-east-1",
        "stack_name": "quilt",
        "ecs_resources": [
            {
                "logical_id": "Cluster",
                "physical_id": "quilt",
                "resource_type": "AWS::ECS::Cluster",
            },
            {
                "logical_id": "RegistryService",
                "physical_id": "registry-service",
                "resource_type": "AWS::ECS::Service",
            },
        ],
        "log_groups": [],
    }
    calls = {}

    monkeypatch.setattr(
        logs_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **_kw: fake,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "ensure_stack_payload",
        lambda catalog, **_kw: payload,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "aws_client",
        lambda service, stack_payload, **_kw: "ecs-client",
    )

    def _set_log_level(ecs_client, **kwargs):
        calls["ecs_client"] = ecs_client
        calls.update(kwargs)
        return {}

    monkeypatch.setattr(logs_tool.ecs_lib, "set_log_level", _set_log_level)

    rc = logs_tool.main(["--catalog", "nightly.quilttest.com", "--set-level"])

    assert rc == 0
    assert calls == {
        "ecs_client": "ecs-client",
        "cluster": "quilt",
        "service": "registry-service",
        "container": None,
        "level": "DEBUG",
        "dry_run": True,
    }


def test_set_level_autocompletes_unique_prefix(monkeypatch) -> None:
    fake = make_fake_catalog("nightly.quilttest.com")
    payload = {
        "region": "us-east-1",
        "stack_name": "quilt",
        "ecs_resources": [
            {
                "logical_id": "Cluster",
                "physical_id": "quilt",
                "resource_type": "AWS::ECS::Cluster",
            },
            {
                "logical_id": "RegistryService",
                "physical_id": "registry-service",
                "resource_type": "AWS::ECS::Service",
            },
        ],
        "log_groups": [],
    }
    calls = {}

    monkeypatch.setattr(
        logs_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **_kw: fake,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "ensure_stack_payload",
        lambda catalog, **_kw: payload,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "aws_client",
        lambda service, stack_payload, **_kw: "ecs-client",
    )

    def _set_log_level(ecs_client, **kwargs):
        calls.update(kwargs)
        return {}

    monkeypatch.setattr(logs_tool.ecs_lib, "set_log_level", _set_log_level)

    rc = logs_tool.main(["--catalog", "nightly.quilttest.com", "--set-level", "D"])

    assert rc == 0
    assert calls["level"] == "DEBUG"


def test_set_level_yes_waits_for_stability(monkeypatch) -> None:
    fake = make_fake_catalog("nightly.quilttest.com")
    payload = {
        "region": "us-east-1",
        "stack_name": "quilt",
        "ecs_resources": [
            {
                "logical_id": "Cluster",
                "physical_id": "quilt",
                "resource_type": "AWS::ECS::Cluster",
            },
            {
                "logical_id": "RegistryService",
                "physical_id": "registry-service",
                "resource_type": "AWS::ECS::Service",
            },
        ],
        "log_groups": [],
    }
    calls = {}

    monkeypatch.setattr(
        logs_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **_kw: fake,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "ensure_stack_payload",
        lambda catalog, **_kw: payload,
    )
    monkeypatch.setattr(
        logs_tool.stack_lib,
        "aws_client",
        lambda service, stack_payload, **_kw: "ecs-client",
    )
    monkeypatch.setattr(logs_tool.ecs_lib, "set_log_level", lambda *a, **kw: {})

    def _wait_for_stable(ecs_client, **kwargs):
        calls["ecs_client"] = ecs_client
        calls.update(kwargs)

    monkeypatch.setattr(logs_tool.status_tool, "wait_for_stable", _wait_for_stable)

    rc = logs_tool.main(
        ["--catalog", "nightly.quilttest.com", "--set-level", "DEBUG", "--yes"]
    )

    assert rc == 0
    assert calls["ecs_client"] == "ecs-client"
    assert calls["cluster"] == "quilt"
    assert calls["service"] == "registry-service"


def test_set_level_rejects_invalid_value_before_stack_lookup(
    monkeypatch, capsys
) -> None:
    called = False

    def _resolve_catalog_context(*_args, **_kwargs):
        nonlocal called
        called = True
        return make_fake_catalog("nightly.quilttest.com")

    monkeypatch.setattr(
        logs_tool.stack_lib,
        "resolve_catalog_context",
        _resolve_catalog_context,
    )

    try:
        logs_tool.main(["--catalog", "nightly.quilttest.com", "--set-level", "nope"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("Expected argparse to exit for invalid log level")

    assert called is False
    assert "invalid log level 'nope'" in capsys.readouterr().err
