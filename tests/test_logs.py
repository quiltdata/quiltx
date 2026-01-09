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
