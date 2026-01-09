"""Quilt catalog logs tool."""

from __future__ import annotations

import argparse
import json as json_lib
import sys
import time
from datetime import datetime, timezone
from typing import Any, Mapping

import boto3
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from quiltx import logs as logs_lib
from quiltx import stack as stack_lib


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Display CloudWatch logs for the configured Quilt catalog."
    )
    parser.add_argument(
        "streams",
        nargs="*",
        help="Log stream names to display (substring match). If not specified, shows all streams.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available log group keys.",
    )
    parser.add_argument(
        "--catalog-name",
        help="Catalog name used in the stack payload path.",
    )
    parser.add_argument(
        "--since",
        help="Start time (ISO 8601 or epoch seconds/millis).",
    )
    parser.add_argument(
        "--until",
        help="End time (ISO 8601 or epoch seconds/millis).",
    )
    parser.add_argument(
        "--minutes",
        type=int,
        help="Look back this many minutes (default 15).",
    )
    parser.add_argument(
        "--hours",
        type=int,
        help="Look back this many hours.",
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Look back this many days.",
    )
    parser.add_argument(
        "--ago",
        type=int,
        help="Start N minutes ago (e.g., --ago 120 --minutes 15 shows logs from 120-105 minutes ago).",
    )
    parser.add_argument(
        "--filter",
        help="CloudWatch Logs filter pattern.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum log entries per log group (default 5). Use 0 for unlimited.",
    )
    parser.add_argument(
        "--follow",
        "-f",
        action="store_true",
        default=True,
        help="Continuously poll for new logs (like tail -f). This is the default behavior.",
    )
    parser.add_argument(
        "--no-follow",
        action="store_false",
        dest="follow",
        help="Disable follow mode and show static logs.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output.",
    )
    parser.add_argument(
        "--wrap",
        action="store_true",
        help="Wrap long messages instead of truncating (default when filtering by stream).",
    )
    return parser


def _list_available_logs(console: Console, payload: Mapping[str, Any]) -> None:
    """Display available log groups with their logical keys."""
    log_entries = payload.get("log_groups", [])
    if not log_entries:
        console.print("[yellow]No log groups found in stack payload.[/yellow]")
        return

    region = payload.get("region", "us-east-1")

    table = Table(show_header=True, header_style="bold cyan", show_lines=False)
    table.add_column("Key", style="green", no_wrap=True)
    table.add_column("Log Group Name", style="dim", overflow="fold")
    table.add_column("Console URL", style="blue", no_wrap=True)

    for entry in log_entries:
        key = entry.get("logical_id", "unknown")
        log_group_name = entry.get("log_group_name", "")

        # Generate AWS Console URL for this log group
        # URL encode the log group name
        import urllib.parse

        encoded_name = urllib.parse.quote(log_group_name, safe="")
        console_url = (
            f"https://{region}.console.aws.amazon.com/cloudwatch/home"
            f"?region={region}#logsV2:log-groups/log-group/{encoded_name}"
        )

        table.add_row(key, log_group_name, f"[link={console_url}]View[/link]")

    console.print("\n[bold cyan]Available Log Groups[/bold cyan]")
    console.print(table)
    console.print("\n[dim]Usage: quiltx logs [STREAM...][/dim]")
    console.print("[dim]Example: quiltx logs registry/registry[/dim]")
    console.print("[dim]Default: quiltx logs (shows all streams)[/dim]")


def _get_all_log_groups(log_entries: list[Mapping[str, Any]]) -> dict[str, str]:
    """Get all log groups from the payload.

    Returns:
        Dict mapping logical_id to log_group_name
    """
    result = {}
    for entry in log_entries:
        logical_id = entry.get("logical_id", "")
        log_group_name = entry.get("log_group_name")
        if logical_id and log_group_name:
            result[logical_id] = log_group_name
    return result


def _get_level_style(level: str) -> str:
    """Get the Rich style for a given log level."""
    return {
        "ERROR": "bold red",
        "WARN": "bold yellow",
        "WARNING": "bold yellow",
        "INFO": "blue",
        "DEBUG": "dim",
    }.get(level, "")


def _coalesce_health_checks(
    events: list[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    """Coalesce consecutive health check log entries into a single summary.

    Replaces consecutive health check entries with a single entry showing
    the most recent timestamp and a count of coalesced checks.
    """
    if not events:
        return events

    result: list[Mapping[str, Any]] = []
    health_check_group: list[Mapping[str, Any]] = []

    for event in events:
        message = event.get("message", "")
        if logs_lib.is_health_check(message):
            health_check_group.append(event)
        else:
            # Flush any accumulated health checks
            if health_check_group:
                # Keep only the most recent health check
                most_recent = health_check_group[-1]
                count = len(health_check_group)
                # Add count to message if more than one
                if count > 1:
                    modified_event = dict(most_recent)
                    modified_event["message"] = (
                        f"[{count} health checks coalesced] "
                        + modified_event.get("message", "")
                    )
                    result.append(modified_event)
                else:
                    result.append(most_recent)
                health_check_group = []
            result.append(event)

    # Flush any remaining health checks at the end
    if health_check_group:
        most_recent = health_check_group[-1]
        count = len(health_check_group)
        if count > 1:
            modified_event = dict(most_recent)
            modified_event["message"] = (
                f"[{count} health checks coalesced] "
                + modified_event.get("message", "")
            )
            result.append(modified_event)
        else:
            result.append(most_recent)

    return result


def _display_log_section(
    console: Console,
    logical_id: str,
    events: list[Mapping[str, Any]],
    limit: int,
) -> None:
    """Display logs for a single log group in a section."""
    if not events:
        return

    # Coalesce health checks first
    events = _coalesce_health_checks(events)

    # Apply limit if specified
    if limit > 0:
        events = events[-limit:]

    # Print section header
    console.print(f"\n[bold cyan]─── {logical_id} ───[/bold cyan]")

    # Print each log entry
    for event in events:
        structured = logs_lib.format_event_structured(event)
        text = Text()

        # Timestamp in dim gray
        text.append(structured["timestamp"], style="dim")
        text.append(" ")

        # Level with color
        level_style = _get_level_style(structured["level"])
        text.append(f"[{structured['level']}]", style=level_style)
        text.append(" ")

        # Message
        text.append(structured["message"])

        console.print(text)


def _display_logs_by_group(
    console: Console,
    logs_client: Any,
    log_groups: dict[str, str],
    start_ms: int,
    end_ms: int,
    filter_pattern: str | None,
    limit: int,
) -> None:
    """Fetch and display logs organized by log stream."""
    for logical_id, log_group_name in log_groups.items():
        # Fetch events for this log group
        events = list(
            logs_lib.iter_log_events(
                logs_client, [log_group_name], start_ms, end_ms, filter_pattern
            )
        )

        if not events:
            continue

        # Group events by log stream
        from collections import defaultdict

        events_by_stream: dict[str, list] = defaultdict(list)

        for event in events:
            structured = logs_lib.format_event_structured(event)
            stream_name = structured["log_stream"]
            if stream_name:  # Only include if we have a stream name
                events_by_stream[stream_name].append(event)

        # Display each stream as its own section
        for stream_name in sorted(events_by_stream.keys()):
            stream_events = events_by_stream[stream_name]
            _display_log_section(console, stream_name, stream_events, limit)


def _follow_logs_dynamic(
    console: Console,
    logs_client: Any,
    log_groups: dict[str, str],
    start_ms: int,
    filter_pattern: str | None,
    payload: Mapping[str, Any],
    wrap: bool = False,
    stream_filters: list[str] | None = None,
) -> None:
    """Follow logs in real-time with dynamic single-screen display.

    Uses Rich Live to create a dynamic display that:
    - Shows recent log entries organized by stream
    - Automatically drops older streams to fit the screen
    - Updates in real-time as new logs arrive
    """
    from collections import defaultdict, deque
    from urllib.parse import urlparse

    last_timestamp = start_ms
    # Store events by stream, keeping only recent ones
    # Key: (logical_id, stream_name), Value: deque of events
    events_by_stream: dict[tuple[str, str], deque[Any]] = defaultdict(
        lambda: deque(maxlen=50)
    )

    # Extract header information
    catalog_url = payload.get("catalog_url", "")
    host = urlparse(catalog_url).hostname or "unknown"
    stack_name = payload.get("stack_name", "unknown")
    region = payload.get("region", "unknown")
    account_id = payload.get("account_id", "unknown")

    def create_display() -> Table:
        """Create a table displaying recent log events."""
        # Get console size
        console_height = console.height or 40
        console_width = console.width or 120

        # Reserve space for header, borders, and status line
        available_lines = max(10, console_height - 7)

        # Collect all events across all streams
        all_events: list[tuple[str, str, Any]] = []
        for (logical_id, stream_name), stream_events in events_by_stream.items():
            for event in stream_events:
                all_events.append((logical_id, stream_name, event))

        # Sort by timestamp (oldest first)
        all_events.sort(key=lambda x: x[2].get("timestamp", 0))

        # Keep only the most recent events that fit on screen
        if len(all_events) > available_lines:
            all_events = all_events[-available_lines:]

        # Group by stream again for display
        display_by_stream: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for logical_id, stream_name, event in all_events:
            display_by_stream[(logical_id, stream_name)].append(event)

        # Create table
        table = Table(
            show_header=False,
            show_edge=False,
            pad_edge=False,
            box=None,
            expand=True,
        )
        table.add_column("content", overflow="fold")

        # Add header with host - stack - region - account
        header_text = Text()
        header_text.append(host, style="bold cyan")
        header_text.append(" - ", style="dim")
        header_text.append(stack_name, style="bold green")
        header_text.append(" - ", style="dim")
        header_text.append(region, style="yellow")
        header_text.append(" - ", style="dim")
        header_text.append(account_id, style="magenta")
        table.add_row(header_text)
        table.add_row("")  # Empty line after header

        # Display events by stream
        for (logical_id, stream_name), display_events in display_by_stream.items():
            if display_events:
                # Add stream header
                header = Text()
                header.append(f"─── {stream_name} ───", style="bold cyan")
                table.add_row(header)

                # Coalesce health checks for this stream
                coalesced_events = _coalesce_health_checks(display_events)

                # Add events
                for event in coalesced_events:
                    structured = logs_lib.format_event_structured(event)
                    text = Text()

                    # Timestamp in dim gray
                    text.append(structured["timestamp"], style="dim")
                    text.append(" ")

                    # Level with color
                    level_style = _get_level_style(structured["level"])
                    text.append(f"[{structured['level']}]", style=level_style)
                    text.append(" ")

                    # Message (truncate if too long, unless wrap is enabled)
                    message = structured["message"]
                    if not wrap:
                        max_msg_len = (
                            console_width - 30
                        )  # Reserve space for timestamp and level
                        if len(message) > max_msg_len:
                            message = message[: max_msg_len - 3] + "..."
                    text.append(message)

                    table.add_row(text)

                # Add spacing between streams
                table.add_row("")

        return table

    # Convert log_groups dict to list for iter_log_events
    log_group_names = list(log_groups.values())

    with Live(console=console, refresh_per_second=2, screen=False) as live:
        try:
            while True:
                now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
                new_events = list(
                    logs_lib.iter_log_events(
                        logs_client,
                        log_group_names,
                        last_timestamp,
                        now_ms,
                        filter_pattern,
                    )
                )

                # Add new events to the appropriate streams
                for event in new_events:
                    structured = logs_lib.format_event_structured(event)
                    log_group_name = event.get("logGroupName", "")
                    stream_name = structured["log_stream"] or "unknown"

                    # Apply stream filters if specified
                    if stream_filters:
                        if not any(sf in stream_name for sf in stream_filters):
                            continue

                    # Find the logical_id for this log group
                    logical_id = "unknown"
                    for lid, lgn in log_groups.items():
                        if lgn == log_group_name:
                            logical_id = lid
                            break

                    # Add to stream's deque
                    stream_key = (logical_id, stream_name)
                    events_by_stream[stream_key].append(event)

                    # Update last timestamp
                    event_ts = event.get("timestamp")
                    if event_ts:
                        last_timestamp = max(last_timestamp, int(event_ts) + 1)

                # Update display
                live.update(create_display())
                time.sleep(2)
        except KeyboardInterrupt:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.catalog_name:
            catalog_name = args.catalog_name
        else:
            import quilt3

            config = quilt3.config()
            if not config:
                raise ValueError("No Quilt catalog configured")
            catalog_name = stack_lib.extract_catalog_name(config)

        payload = logs_lib.load_stack_payload(catalog_name)

        # Create console for Rich output
        console = Console(force_terminal=not args.no_color)

        # Handle --list flag
        if args.list:
            _list_available_logs(console, payload)
            return 0

        # Get all log groups from payload
        log_entries = payload.get("log_groups", [])
        log_groups = _get_all_log_groups(log_entries)

        if not log_groups:
            console.print("[red]Error:[/red] No log groups found in stack payload")
            console.print(
                "\n[dim]Run 'quiltx logs --list' to see available log groups.[/dim]"
            )
            return 1

        # Determine stream filters from positional arguments
        stream_filters = args.streams if args.streams else None

        region = payload.get("region")
        if not region:
            raise ValueError("Region missing from stack payload")

        start_ms, end_ms = logs_lib.resolve_time_range(
            args.since, args.until, args.minutes, args.hours, args.days, args.ago
        )

        logs_client = boto3.client("logs", region_name=region)

        # Auto-enable wrap when stream filter is specified
        wrap = args.wrap or bool(stream_filters)

        # Handle follow mode vs static display
        if args.follow:
            _follow_logs_dynamic(
                console,
                logs_client,
                log_groups,
                start_ms,
                args.filter,
                payload,
                wrap,
                stream_filters,
            )
        else:
            # Display static logs organized by group
            _display_logs_by_group(
                console,
                logs_client,
                log_groups,
                start_ms,
                end_ms,
                args.filter,
                args.limit,
            )

        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
