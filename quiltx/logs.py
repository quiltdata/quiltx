"""CloudWatch Logs helpers for Quilt stacks."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from platformdirs import user_data_path


def load_stack_payload(catalog_name: str) -> Mapping[str, Any]:
    payload_path = user_data_path("quiltx") / catalog_name / "stack.json"
    if not payload_path.exists():
        raise FileNotFoundError(f"Missing stack payload at {payload_path}")
    return json.loads(payload_path.read_text())


def parse_time(value: str) -> datetime:
    value = value.strip()
    if value.isdigit():
        epoch = int(value)
        if epoch > 10**12:
            return datetime.fromtimestamp(epoch / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(epoch, tz=timezone.utc)

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_time_range(
    since: str | None,
    until: str | None,
    minutes: int | None,
    hours: int | None,
    days: int | None,
) -> tuple[int, int]:
    now = datetime.now(timezone.utc)

    if since or until:
        start = parse_time(since) if since else now - timedelta(hours=1)
        end = parse_time(until) if until else now
        return int(start.timestamp() * 1000), int(end.timestamp() * 1000)

    total_minutes = 0
    if minutes:
        total_minutes += minutes
    if hours:
        total_minutes += hours * 60
    if days:
        total_minutes += days * 24 * 60

    if total_minutes == 0:
        total_minutes = 60

    start = now - timedelta(minutes=total_minutes)
    return int(start.timestamp() * 1000), int(now.timestamp() * 1000)


def iter_log_events(
    logs_client,
    log_groups: Sequence[str],
    start_ms: int,
    end_ms: int,
    filter_pattern: str | None = None,
) -> Iterable[Mapping[str, Any]]:
    for log_group in log_groups:
        paginator = logs_client.get_paginator("filter_log_events")
        params: dict[str, Any] = {
            "logGroupName": log_group,
            "startTime": start_ms,
            "endTime": end_ms,
        }
        if filter_pattern:
            params["filterPattern"] = filter_pattern

        for page in paginator.paginate(**params):
            for event in page.get("events", []):
                yield event


def format_event(event: Mapping[str, Any]) -> str:
    timestamp = event.get("timestamp")
    if timestamp is None:
        ts = "unknown"
    else:
        ts = datetime.fromtimestamp(int(timestamp) / 1000, tz=timezone.utc).isoformat()
    group = event.get("logGroupName") or event.get("logStreamName", "unknown")
    message = event.get("message", "").rstrip("\n")
    return f"{ts} {group} {message}"
