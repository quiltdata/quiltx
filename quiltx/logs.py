"""CloudWatch Logs helpers for Quilt stacks."""

from __future__ import annotations

import json
import re
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
    ago: int | None = None,
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
        total_minutes = 15

    # If --ago is specified, shift the time window back
    if ago:
        end = now - timedelta(minutes=ago)
        start = end - timedelta(minutes=total_minutes)
    else:
        start = now - timedelta(minutes=total_minutes)
        end = now

    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)


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


def is_health_check(message: str) -> bool:
    """Check if a log message is a health check request.

    Health checks are identified by:
    - ELB-HealthChecker user agent
    - GET / or GET /healthcheck requests with 200 status
    """
    msg_lower = message.lower()
    return "elb-healthchecker" in msg_lower or (
        ("get /" in msg_lower or "get /healthcheck" in msg_lower) and "200" in message
    )


def parse_log_level(message: str) -> tuple[str, str]:
    """Extract log level from message and return (level, remaining_message).

    Returns:
        Tuple of (level, message) where level is one of ERROR, WARN, WARNING, INFO, DEBUG
        or INFO if no level is found. The message is the original message with the level
        prefix removed if it was found.
    """
    # Match log level at the start of the message
    match = re.match(
        r"^\s*\[?(ERROR|WARN|WARNING|INFO|DEBUG)\]?[:\s-]+(.*)$", message, re.IGNORECASE
    )
    if match:
        level = match.group(1).upper()
        remaining = match.group(2)
        # Normalize WARNING to WARN
        if level == "WARNING":
            level = "WARN"
        return level, remaining

    # Look for log level anywhere in the first part of the message
    match = re.search(
        r"\b(ERROR|WARN|WARNING|INFO|DEBUG)\b", message[:100], re.IGNORECASE
    )
    if match:
        level = match.group(1).upper()
        if level == "WARNING":
            level = "WARN"
        return level, message

    # Default to INFO if no level found
    return "INFO", message


def format_event_structured(event: Mapping[str, Any]) -> dict[str, Any]:
    """Format a CloudWatch log event into structured fields for display.

    Returns:
        Dictionary with keys: timestamp, log_group, log_stream, level, message
    """
    timestamp = event.get("timestamp")
    if timestamp is None:
        ts = "unknown"
    else:
        # Convert to local time for display in human-friendly format
        dt = datetime.fromtimestamp(int(timestamp) / 1000, tz=timezone.utc)
        local_dt = dt.astimezone()
        # Format as "Jan 08 5:51:50 PM"
        ts = local_dt.strftime("%b %d %I:%M:%S %p")

    log_group = event.get("logGroupName", "")
    log_stream = event.get("logStreamName", "")
    message = event.get("message", "").rstrip("\n")

    # Parse log level from message
    level, parsed_message = parse_log_level(message)

    # Extract meaningful log stream name
    # Format is typically: service/component/hash or container/container/hash
    # We want to keep the service/component part, drop the hash
    short_stream = ""
    if log_stream:
        parts = log_stream.split("/")
        if len(parts) >= 3:
            # Keep first two parts (e.g., "s3-proxy/s3-proxy", "benchling/benchling")
            short_stream = f"{parts[0]}/{parts[1]}"
        elif len(parts) == 2:
            # Keep first part
            short_stream = parts[0]
        else:
            # Just use the whole thing
            short_stream = log_stream

    return {
        "timestamp": ts,
        "log_group": log_group,
        "log_stream": short_stream,
        "level": level,
        "message": parsed_message,
    }


def format_event(event: Mapping[str, Any]) -> str:
    """Format a CloudWatch log event as a single line string (legacy format)."""
    timestamp = event.get("timestamp")
    if timestamp is None:
        ts = "unknown"
    else:
        ts = datetime.fromtimestamp(int(timestamp) / 1000, tz=timezone.utc).isoformat()
    group = event.get("logGroupName") or event.get("logStreamName", "unknown")
    message = event.get("message", "").rstrip("\n")
    return f"{ts} {group} {message}"
