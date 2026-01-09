"""Stack discovery helpers for Quilt catalogs."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlparse, urlunparse

from platformdirs import user_data_path


def normalize_catalog_url(url: str) -> str:
    url = url.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        normalized = urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/"),
                "",
                "",
                "",
            )
        )
        return normalized.rstrip("/")
    return url


def normalize_host(value: str) -> str:
    value = value.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.hostname.lower() if parsed.hostname else value.lower()
    return value.lower()


def extract_catalog_name(config: Mapping[str, Any]) -> str:
    catalog_name = config.get("catalog")
    if catalog_name:
        return str(catalog_name)

    navigator_url = config.get("navigator_url")
    if not navigator_url:
        raise ValueError("navigator_url not set in Quilt config")

    parsed = urlparse(str(navigator_url))
    if not parsed.hostname:
        raise ValueError(f"Invalid navigator_url: {navigator_url}")

    return parsed.hostname


def fetch_catalog_config(
    catalog_url: str, opener: Callable[[str], Any] = urllib.request.urlopen
) -> Mapping[str, Any]:
    config_url = catalog_url.rstrip("/") + "/config.json"
    with opener(config_url) as response:
        return json.load(response)


def resolve_region(config: Mapping[str, Any], catalog_config: Mapping[str, Any]) -> str:
    region = catalog_config.get("region") or config.get("region")
    if not region:
        raise ValueError("No region found in catalog config or local config")
    return str(region)


def stack_outputs(stack: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    return stack.get("Outputs") or []


def stack_parameters(stack: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    return stack.get("Parameters") or []


def find_matching_stack(cfn_client, catalog_url: str) -> Mapping[str, Any]:
    expected_host = normalize_host(catalog_url)
    paginator = cfn_client.get_paginator("describe_stacks")

    output_host_matches = []

    for page in paginator.paginate():
        for stack in page.get("Stacks", []):
            for output in stack_outputs(stack):
                output_key = str(output.get("OutputKey", "")).lower()
                output_value = output.get("OutputValue")
                if not output_value:
                    continue
                if output_key == "quiltwebhost":
                    if normalize_host(str(output_value)) == expected_host:
                        output_host_matches.append(stack)

    if output_host_matches:
        return output_host_matches[0]

    raise ValueError("No stack found with QuiltWebHost matching " f"{catalog_url}")


def list_log_group_resources(cfn_client, stack_name: str) -> list[dict[str, str]]:
    paginator = cfn_client.get_paginator("list_stack_resources")
    log_groups = []

    for page in paginator.paginate(StackName=stack_name):
        for resource in page.get("StackResourceSummaries", []):
            if resource.get("ResourceType") != "AWS::Logs::LogGroup":
                continue
            log_groups.append(
                {
                    "logical_id": resource.get("LogicalResourceId", ""),
                    "log_group_name": resource.get("PhysicalResourceId", ""),
                }
            )

    return log_groups


def stack_account_id(stack: Mapping[str, Any]) -> str | None:
    stack_id = stack.get("StackId")
    if not stack_id:
        return None
    parts = str(stack_id).split(":")
    if len(parts) >= 5:
        return parts[4]
    return None


def write_stack_payload(
    catalog_name: str,
    catalog_url: str,
    region: str,
    stack: Mapping[str, Any],
    log_groups: list[dict[str, str]],
) -> Path:
    target_dir = user_data_path("quiltx") / catalog_name
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = target_dir / "stack.json"

    payload = {
        "catalog_name": catalog_name,
        "catalog_url": catalog_url,
        "web_url": catalog_url,
        "region": region,
        "account_id": stack_account_id(stack),
        "stack_name": stack.get("StackName"),
        "stack_id": stack.get("StackId"),
        "outputs": stack.get("Outputs") or [],
        "parameters": stack.get("Parameters") or [],
        "log_groups": log_groups,
    }

    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return output_path
