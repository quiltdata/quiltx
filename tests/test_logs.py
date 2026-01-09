"""Tests for the logs helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3
from botocore.stub import Stubber

from quiltx import logs


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
    monkeypatch.setattr(logs, "user_data_path", lambda *_args, **_kwargs: tmp_path)
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

    events = list(logs.iter_log_events(client, ["/aws/lambda/a"], 1, 2, "ERROR"))
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
