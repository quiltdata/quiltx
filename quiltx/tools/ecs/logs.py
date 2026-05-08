"""Quilt catalog logs tool (under `quiltx ecs logs`).

Displays CloudWatch logs for the configured Quilt catalog, and optionally
sets the container log level via `--set-level`.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from typing import Any, Mapping

from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from quiltx import ecs as ecs_lib
from quiltx import logs as logs_lib
from quiltx import stack as stack_lib
from quiltx.cli_common import add_catalog_args
from quiltx.tools.ecs import status as status_tool

_LOG_LEVELS = ("DEBUG", "INFO", "WARN", "ERROR")
_LOG_LEVEL_ALIASES = {"WARNING": "WARN"}


def _normalize_set_level(value: str) -> str:
    """Normalize a --set-level value, accepting unique prefixes."""
    candidate = value.strip().upper()
    if not candidate:
        raise argparse.ArgumentTypeError(
            f"invalid log level {value!r}; expected one of {', '.join(_LOG_LEVELS)}"
        )
    if candidate in _LOG_LEVEL_ALIASES:
        return _LOG_LEVEL_ALIASES[candidate]
    if candidate in _LOG_LEVELS:
        return candidate

    matches = [level for level in _LOG_LEVELS if level.startswith(candidate)]
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise argparse.ArgumentTypeError(
            f"ambiguous log level {value!r}; matches {', '.join(matches)}"
        )
    raise argparse.ArgumentTypeError(
        f"invalid log level {value!r}; expected one of {', '.join(_LOG_LEVELS)}"
    )


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
    add_catalog_args(parser, auth_required=False)
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
    parser.add_argument(
        "--set-level",
        dest="set_level",
        nargs="?",
        const="DEBUG",
        type=_normalize_set_level,
        help="Set the container log level (default DEBUG). Prompts unless --yes or --dry-run is provided.",
    )
    parser.add_argument(
        "--reset-level",
        action="store_true",
        help="Remove QUILT_LOG_LEVEL from the target container.",
    )
    parser.add_argument(
        "--service",
        help="ECS service to update (defaults to RegistryService from the stack payload).",
    )
    parser.add_argument(
        "--container",
        help="Container to update (defaults to the first container in the task definition).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Apply --set-level without prompting.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Summarize the --set-level update without applying it.",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for ECS service stability after applying --set-level.",
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

        import urllib.parse

        encoded_name = urllib.parse.quote(log_group_name, safe="")
        console_url = (
            f"https://{region}.console.aws.amazon.com/cloudwatch/home"
            f"?region={region}#logsV2:log-groups/log-group/{encoded_name}"
        )

        table.add_row(key, log_group_name, f"[link={console_url}]View[/link]")

    console.print("\n[bold cyan]Available Log Groups[/bold cyan]")
    console.print(table)
    console.print("\n[dim]Usage: quiltx ecs logs [STREAM...][/dim]")
    console.print("[dim]Example: quiltx ecs logs registry/registry[/dim]")
    console.print("[dim]Default: quiltx ecs logs (shows all streams)[/dim]")


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
    """Coalesce consecutive health check log entries into a single summary."""
    if not events:
        return events

    result: list[Mapping[str, Any]] = []
    health_check_group: list[Mapping[str, Any]] = []

    for event in events:
        message = event.get("message", "")
        if logs_lib.is_health_check(message):
            health_check_group.append(event)
        else:
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
                health_check_group = []
            result.append(event)

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

    events = _coalesce_health_checks(events)

    if limit > 0:
        events = events[-limit:]

    console.print(f"\n[bold cyan]─── {logical_id} ───[/bold cyan]")

    for event in events:
        structured = logs_lib.format_event_structured(event)
        text = Text()

        text.append(structured["timestamp"], style="dim")
        text.append(" ")

        level_style = _get_level_style(structured["level"])
        text.append(f"[{structured['level']}]", style=level_style)
        text.append(" ")

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
        events = list(
            logs_lib.iter_log_events(
                [log_group_name],
                start_ms,
                end_ms,
                filter_pattern,
                logs_client=logs_client,
            )
        )

        if not events:
            continue

        from collections import defaultdict

        events_by_stream: dict[str, list] = defaultdict(list)

        for event in events:
            structured = logs_lib.format_event_structured(event)
            stream_name = structured["log_stream"]
            if stream_name:
                events_by_stream[stream_name].append(event)

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
    """Follow logs in real-time with dynamic single-screen display."""
    from collections import defaultdict, deque
    from urllib.parse import urlparse

    last_timestamp = start_ms
    events_by_stream: dict[tuple[str, str], deque[Any]] = defaultdict(
        lambda: deque(maxlen=50)
    )

    catalog_url = payload.get("catalog_url", "")
    host = urlparse(catalog_url).hostname or "unknown"
    stack_name = payload.get("stack_name", "unknown")
    region = payload.get("region", "unknown")
    account_id = payload.get("account_id", "unknown")

    def create_display() -> Table:
        console_height = console.height or 40
        console_width = console.width or 120

        available_lines = max(10, console_height - 7)

        all_events: list[tuple[str, str, Any]] = []
        for (logical_id, stream_name), stream_events in events_by_stream.items():
            for event in stream_events:
                all_events.append((logical_id, stream_name, event))

        all_events.sort(key=lambda x: x[2].get("timestamp", 0))

        if len(all_events) > available_lines:
            all_events = all_events[-available_lines:]

        display_by_stream: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for logical_id, stream_name, event in all_events:
            display_by_stream[(logical_id, stream_name)].append(event)

        table = Table(
            show_header=False,
            show_edge=False,
            pad_edge=False,
            box=None,
            expand=True,
        )
        table.add_column("content", overflow="fold")

        header_text = Text()
        header_text.append(host, style="bold cyan")
        header_text.append(" - ", style="dim")
        header_text.append(stack_name, style="bold green")
        header_text.append(" - ", style="dim")
        header_text.append(region, style="yellow")
        header_text.append(" - ", style="dim")
        header_text.append(account_id, style="magenta")
        table.add_row(header_text)
        table.add_row("")

        for (logical_id, stream_name), display_events in display_by_stream.items():
            if display_events:
                header = Text()
                header.append(f"─── {stream_name} ───", style="bold cyan")
                table.add_row(header)

                coalesced_events = _coalesce_health_checks(display_events)

                for event in coalesced_events:
                    structured = logs_lib.format_event_structured(event)
                    text = Text()

                    text.append(structured["timestamp"], style="dim")
                    text.append(" ")

                    level_style = _get_level_style(structured["level"])
                    text.append(f"[{structured['level']}]", style=level_style)
                    text.append(" ")

                    message = structured["message"]
                    if not wrap:
                        max_msg_len = max(160, console_width - 30)
                        if len(message) > max_msg_len:
                            message = message[: max_msg_len - 3] + "..."
                    text.append(message)

                    table.add_row(text)

                table.add_row("")

        return table

    log_group_names = list(log_groups.values())

    with Live(console=console, refresh_per_second=2, screen=False) as live:
        try:
            while True:
                now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
                new_events = list(
                    logs_lib.iter_log_events(
                        log_group_names,
                        last_timestamp,
                        now_ms,
                        filter_pattern,
                        logs_client=logs_client,
                    )
                )

                for event in new_events:
                    structured = logs_lib.format_event_structured(event)
                    log_group_name = event.get("logGroupName", "")
                    stream_name = structured["log_stream"] or "unknown"

                    if stream_filters:
                        if not any(sf in stream_name for sf in stream_filters):
                            continue

                    logical_id = "unknown"
                    for lid, lgn in log_groups.items():
                        if lgn == log_group_name:
                            logical_id = lid
                            break

                    stream_key = (logical_id, stream_name)
                    events_by_stream[stream_key].append(event)

                    event_ts = event.get("timestamp")
                    if event_ts:
                        last_timestamp = max(last_timestamp, int(event_ts) + 1)

                live.update(create_display())
                time.sleep(2)
        except KeyboardInterrupt:
            pass


def _render_log_level_plan(plan: ecs_lib.LogLevelPlan) -> Table:
    table = Table(title="ECS Log Level Update", show_lines=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Action", plan.action)
    table.add_row("Cluster", plan.cluster)
    table.add_row("Service", plan.service)
    table.add_row("Container", plan.container)
    table.add_row("Current task definition", plan.current_task_definition)
    table.add_row("Current level", plan.current_level or "<unset>")
    table.add_row("New level", plan.level or "<unset>")
    table.add_row("Deployment", "register new task definition and force deployment")
    return table


@stack_lib.catalog_command(auth=False)
def _run(catalog: stack_lib.Catalog, args: Any) -> int:
    payload = stack_lib.ensure_stack_payload(
        catalog,
        announce=lambda message: print(message, file=sys.stderr),
    )

    console = Console(force_terminal=not args.no_color)

    if getattr(args, "set_level", None) or getattr(args, "reset_level", False):
        cluster = stack_lib.require_ecs_cluster(payload)
        service = args.service or stack_lib.require_registry_service(payload)
        ecs_client = stack_lib.aws_client("ecs", payload)
        level = None if args.reset_level else args.set_level
        plan = ecs_lib.build_log_level_plan(
            ecs_client,
            cluster=cluster,
            service=service,
            container=args.container,
            level=level,
        )
        console.print(_render_log_level_plan(plan))
        if args.dry_run:
            return 0
        if not args.yes:
            if not Confirm.ask("Apply this update?", default=False):
                console.print("Aborted.")
                return 1
        result = ecs_lib.apply_log_level_plan(ecs_client, plan)
        console.print(
            f"Updated {service} to {result.task_definition_arn} "
            f"with QUILT_LOG_LEVEL={level or '<unset>'}"
        )
        if not args.no_wait:
            status_tool.wait_for_stable(
                ecs_client,
                cluster=cluster,
                service=service,
                console=console,
            )
        return 0

    if args.list:
        _list_available_logs(console, payload)
        return 0

    log_groups = stack_lib.log_groups(payload)

    if not log_groups:
        console.print("[red]Error:[/red] No log groups found in stack payload")
        console.print(
            "\n[dim]Run 'quiltx ecs logs --list' to see available log groups.[/dim]"
        )
        return 1

    stream_filters = args.streams if args.streams else None

    region = stack_lib.require_region(payload)

    start_ms, end_ms = logs_lib.resolve_time_range(
        args.since, args.until, args.minutes, args.hours, args.days, args.ago
    )

    logs_client = stack_lib.aws_client("logs", payload, region=region)

    wrap = args.wrap or bool(stream_filters)

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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
