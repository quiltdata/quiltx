"""Catalog identity, payload cache, and CloudFormation discovery helpers."""

from __future__ import annotations

import functools
import json
import os
import ssl
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, TypeVar, overload
from urllib.parse import urlparse

from platformdirs import user_data_path

from quiltx._version import __version__
from quiltx.identity import normalize_dns
from quiltx.utils import get_hostname

CatalogContextSource = Literal["flag", "env", "default", "global-config"]


@dataclass(frozen=True)
class CatalogContext:
    catalog_name: str
    catalog_url: str
    source: CatalogContextSource


@dataclass(frozen=True)
class AdminClients:
    buckets: Any
    policies: Any
    roles: Any
    sso_config: Any
    users: Any


@dataclass(frozen=True)
class Catalog(CatalogContext):
    # When False, ensure_auth() is a no-op (set by @catalog_command(auth=False) path).
    auth_required: bool = field(default=True)
    _admin: AdminClients | None = field(default=None, init=False, repr=False)
    _region: str | None = field(default=None, init=False, repr=False)
    # API-path API key passed via Catalog.from_dns(api_key=...).
    # Used as the first step of the API resolver ladder; never set on the CLI path.
    _api_key: str | None = field(default=None, init=False, repr=False)

    @property
    def region(self) -> str:
        if self._region is None:
            object.__setattr__(self, "_region", fetch_region(self))
        assert self._region is not None
        return self._region

    @property
    def admin(self) -> AdminClients:
        # ensure_auth() is a no-op if auth=False was set; when active it binds
        # quilt3's global state to this catalog before we access admin modules.
        self.ensure_auth()
        if self._admin is None:
            from quiltx.quilt3_facade import admin_modules

            clients = admin_modules()
            object.__setattr__(
                self,
                "_admin",
                AdminClients(
                    buckets=clients.buckets,
                    policies=clients.policies,
                    roles=clients.roles,
                    sso_config=clients.sso_config,
                    users=clients.users,
                ),
            )
        assert self._admin is not None
        return self._admin

    @property
    def payload(self) -> Mapping[str, Any] | None:
        return load_stack_payload(self.catalog_name)

    def aws_session(self, *, profile: str | None = None) -> Any:
        """Return a plain boto3 session for AWS operations on this catalog.

        Per spec [06 §3.3]: never imports quilt3 and never reads
        Quilt-issued AWS credentials from credentials.json.
        """
        import boto3

        return boto3.Session(profile_name=profile, region_name=self._region)

    def cfn_client(self, region: str | None = None) -> Any:
        import boto3

        return boto3.client("cloudformation", region_name=region or self._region)

    def ensure_auth(self, args: Any = None, *, skip_keyring: bool = False) -> None:
        """Bind quilt3's in-process session to this catalog.

        Per spec [05 §5] / [06 §3.1]:
        1. Resolve a single API key from the resolver ladder.
        2. Bind catalog URL via ContextVar override (no config.yml write).
        3. Call login_with_api_key().

        ``skip_keyring`` is set by the retry envelope after an auth failure
        so the resolver re-prompts instead of replaying the bad keyring entry
        ([06 §5 step 3]).
        """
        if not self.auth_required:
            return

        from quiltx.auth import CredentialError, resolve_api, resolve_cli
        from quiltx.quilt3_facade import (
            _QUILT3_LOCK,
            bind_active_catalog,
            login_with_api_key,
        )

        if args is not None:
            try:
                resolved = resolve_cli(self, args, skip_keyring=skip_keyring)
            except CredentialError as exc:
                raise ValueError(str(exc)) from exc
        else:
            try:
                resolved = resolve_api(
                    self,
                    api_key=self._api_key,
                    skip_keyring=skip_keyring,
                )
            except CredentialError as exc:
                raise ValueError(str(exc)) from exc

        with _QUILT3_LOCK:
            bind_active_catalog(self.catalog_url)
            login_with_api_key(resolved.api_key)

    @classmethod
    def from_dns(
        cls,
        dns: str,
        *,
        source: CatalogContextSource,
        auth_required: bool = True,
        api_key: str | None = None,
        insecure: bool = False,
    ) -> "Catalog":
        """Build a Catalog from a bare DNS name.

        ``api_key`` is the Story 5 API-path credential; it feeds step 1 of
        the API resolver ladder and is used lazily on the first
        ``ensure_auth()`` call.

        ``insecure=True`` is a localhost-only escape hatch that switches the
        catalog URL to ``http://localhost`` for testing local catalog builds.
        Refused for any non-localhost target.
        """
        from quiltx.identity import build_catalog_url

        catalog = cls(
            catalog_name=dns,
            catalog_url=build_catalog_url(dns, insecure=insecure),
            source=source,
            auth_required=auth_required,
        )
        if api_key is not None:
            object.__setattr__(catalog, "_api_key", api_key)
        return catalog


T = TypeVar("T")


def _is_auth_error(exc: Exception) -> bool:
    return "Authentication failed" in str(exc)


def _verbose_active(parsed_args: Any) -> bool:
    """Return True when verbose output is requested."""
    if os.environ.get("QUILTX_VERBOSE"):
        return True
    return bool(getattr(parsed_args, "verbose", False))


def _probe_auth_source(catalog: "Catalog", parsed_args: Any) -> str:
    """Return a short label describing the credential source.

    Pure inspection — never prompts, never writes to keyring.
    """
    from quiltx import credentials as creds_module

    if getattr(parsed_args, "api_key", None):
        return "flag"
    if os.environ.get("QUILTX_API_KEY"):
        return "env"
    if creds_module.has_credentials(catalog.catalog_name):
        return "keyring"
    return "none"


def _print_verbose_preflight(
    catalog: "Catalog",
    parsed_args: Any,
    auth: bool,
    bootstrap: bool = False,
) -> None:
    """Print the four-line verbose preflight block to stderr."""
    if auth:
        auth_label = _probe_auth_source(catalog, parsed_args)
    elif bootstrap:
        auth_label = "none-needed (bootstrap)"
    else:
        auth_label = "aws-default-chain"

    lines = [
        f"catalog:  {catalog.catalog_name}",
        f"source:   {catalog.source}",
        f"auth:     {auth_label}",
    ]

    # Only print region if it was already resolved (avoid triggering the HTTP fetch).
    region_cached = catalog._region
    if region_cached is not None:
        lines.append(f"region:   {region_cached}")

    for line in lines:
        print(line, file=sys.stderr)


@overload
def catalog_command(func: Callable[..., T]) -> Callable[..., T]: ...


@overload
def catalog_command(
    *, auth: bool = True, bootstrap: bool = False
) -> Callable[[Callable[..., T]], Callable[..., T]]: ...


def catalog_command(
    func: Callable[..., T] | None = None,
    *,
    auth: bool = True,
    bootstrap: bool = False,
) -> Callable[..., T] | Callable[[Callable[..., T]], Callable[..., T]]:
    """Resolve and inject a Catalog into a parsed CLI command handler.

    ``bootstrap=True`` is meaningful only when ``auth=False``. It changes the
    verbose preflight's auth label from ``aws-default-chain`` to
    ``none-needed (bootstrap)`` for commands like ``quiltx catalog stack``
    that establish state rather than consume it.
    """

    def decorate(wrapped: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(wrapped)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            parsed_args = args[0] if args else kwargs.get("args")
            catalog_arg = getattr(parsed_args, "catalog", None)
            insecure = bool(getattr(parsed_args, "insecure", False))
            catalog = resolve_catalog_context(
                catalog_arg, auth_required=auth, insecure=insecure
            )

            if _verbose_active(parsed_args):
                _print_verbose_preflight(catalog, parsed_args, auth, bootstrap)

            def invoke() -> T:
                if auth:
                    catalog.ensure_auth(parsed_args)
                return wrapped(catalog, *args, **kwargs)

            if not auth:
                return invoke()

            try:
                return invoke()
            except Exception as exc:
                if not _is_auth_error(exc):
                    raise
                print(
                    f"Session expired for {catalog.catalog_name}. Re-authenticating...",
                    file=sys.stderr,
                )
                # Per-catalog retry: re-run ensure_auth, skipping the keyring
                # entry that just failed so the resolver falls through to
                # prompt / env / flag (spec 06 §5 step 3).
                catalog.ensure_auth(parsed_args, skip_keyring=True)
                return wrapped(catalog, *args, **kwargs)

        return wrapper

    if func is not None:
        return decorate(func)
    return decorate


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


def _lookup_default_dns() -> str | None:
    """Return the default catalog DNS name, or None if unconfigured.

    Resolution order:
    1. quiltx userconfig (default_catalog key).
    2. Bootstrap: if userconfig is empty and quilt3.config() has a catalog,
       copy that DNS into userconfig once and return it.
    """
    from quiltx import userconfig
    from quiltx.quilt3_facade import current_global_config

    dns = userconfig.get_default_catalog()
    if dns is not None:
        return dns

    # Bootstrap: read quilt3.config() once and persist it.
    config = current_global_config()
    if not config:
        return None
    try:
        dns = extract_catalog_name(config)
    except ValueError:
        return None
    userconfig.set_default_catalog(dns)
    return dns


def resolve_catalog_context(
    catalog: str | None = None,
    *,
    auth_required: bool = True,
    insecure: bool = False,
) -> Catalog:
    """Resolve the target catalog identity.

    Resolution ladder:
    1. ``catalog`` argument (from --catalog flag)
    2. QUILTX_CATALOG env var
    3. quiltx default catalog (userconfig, with quilt3.config() bootstrap)
    4. Error

    ``insecure=True`` selects http://localhost transport (rejected by
    ``normalize_dns`` for any non-localhost target).
    """
    if catalog:
        return Catalog.from_dns(
            normalize_dns(catalog, insecure=insecure),
            source="flag",
            auth_required=auth_required,
            insecure=insecure,
        )

    env_catalog = os.environ.get("QUILTX_CATALOG")
    if env_catalog:
        return Catalog.from_dns(
            normalize_dns(env_catalog, insecure=insecure),
            source="env",
            auth_required=auth_required,
            insecure=insecure,
        )

    dns = _lookup_default_dns()
    if dns is None:
        raise ValueError(
            "No catalog specified and no default configured. "
            "Pass --catalog or run `quiltx catalog default <dns>`."
        )

    if insecure:
        # Sanity: --insecure with the userconfig default is only valid if
        # that default is localhost. normalize_dns enforces this.
        normalize_dns(dns, insecure=True)

    return Catalog.from_dns(
        dns, source="default", auth_required=auth_required, insecure=insecure
    )


def fetch_region(
    ctx: CatalogContext, catalog_config: Mapping[str, Any] | None = None
) -> str:
    """Fetch the AWS region for a resolved catalog context."""
    if catalog_config is None:
        catalog_config = fetch_catalog_config(ctx.catalog_url)
    if ctx.source == "flag":
        region = catalog_config.get("region")
        if not region:
            raise ValueError(
                f"No region found in catalog config for {ctx.catalog_name}"
            )
        return str(region)

    from quiltx.quilt3_facade import current_global_config

    return resolve_region(current_global_config() or {}, catalog_config)


def _default_ssl_context() -> ssl.SSLContext | None:
    """Build an SSL context honoring SSL_CERT_FILE/REQUESTS_CA_BUNDLE if set."""
    ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle and os.path.isfile(ca_bundle):
        return ssl.create_default_context(cafile=ca_bundle)
    return None


def fetch_catalog_config(
    catalog_url: str, opener: Callable[..., Any] = urllib.request.urlopen
) -> Mapping[str, Any]:
    config_url = catalog_url.rstrip("/") + "/config.json"
    context = _default_ssl_context()
    kwargs = {"context": context} if context is not None else {}
    with opener(config_url, **kwargs) as response:
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


def find_matching_stack(
    catalog: Catalog,
    region: str | None = None,
    cfn_client: Any = None,
) -> Mapping[str, Any]:
    """Find the CloudFormation stack backing a catalog.

    Args:
        catalog: Catalog whose CFN stack we're looking up
        region: AWS region (defaults to fetching from catalog config if not provided)
        cfn_client: Optional CloudFormation client (creates one if not provided)

    Returns:
        CFN stack information dictionary

    Raises:
        ValueError: If no matching stack is found
    """
    # Auto-detect region from catalog config if not provided
    if region is None and cfn_client is None:
        try:
            catalog_config = fetch_catalog_config(catalog.catalog_url)
            region = catalog_config.get("region")
            if not region:
                raise ValueError(
                    f"No region found in catalog config for {catalog.catalog_url}. "
                    "Please provide region parameter explicitly."
                )
        except Exception as exc:
            raise ValueError(
                f"Could not auto-detect region for {catalog.catalog_url}: {exc}. "
                "Please provide region parameter explicitly."
            ) from exc

    # Create CloudFormation client if not provided
    if cfn_client is None:
        cfn_client = catalog.cfn_client(region)

    expected_host = catalog.catalog_name
    paginator = cfn_client.get_paginator("describe_stacks")

    output_host_matches = []

    for page in paginator.paginate():
        for stack_info in page.get("Stacks", []):
            for output in stack_outputs(stack_info):
                output_key = str(output.get("OutputKey", "")).lower()
                output_value = output.get("OutputValue")
                if not output_value:
                    continue
                if output_key == "quiltwebhost":
                    if get_hostname(str(output_value)) == expected_host:
                        output_host_matches.append(stack_info)

    if output_host_matches:
        return output_host_matches[0]

    raise ValueError(f"No stack found with QuiltWebHost matching {catalog.catalog_url}")


def list_log_group_resources(
    catalog: Catalog,
    stack_name: str,
    region: str | None = None,
    cfn_client: Any = None,
) -> list[dict[str, str]]:
    """List CloudWatch log groups in a CloudFormation stack.

    Args:
        catalog: Catalog whose AWS session is used to query CloudFormation
        stack_name: CloudFormation stack name
        region: AWS region (required if cfn_client not provided)
        cfn_client: Optional CloudFormation client (creates one if not provided)

    Returns:
        List of log group resource dictionaries
    """
    if cfn_client is None:
        if region is None:
            raise ValueError("Either region or cfn_client must be provided")
        cfn_client = catalog.cfn_client(region)

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


def list_ecs_resources(
    catalog: Catalog,
    stack_name: str,
    region: str | None = None,
    cfn_client: Any = None,
) -> list[dict[str, str]]:
    """List ECS resources in a CloudFormation stack.

    Args:
        catalog: Catalog whose AWS session is used to query CloudFormation
        stack_name: CloudFormation stack name
        region: AWS region (required if cfn_client not provided)
        cfn_client: Optional CloudFormation client (creates one if not provided)

    Returns:
        List of ECS resource dictionaries
    """
    if cfn_client is None:
        if region is None:
            raise ValueError("Either region or cfn_client must be provided")
        cfn_client = catalog.cfn_client(region)

    paginator = cfn_client.get_paginator("list_stack_resources")
    ecs_resources: list[dict[str, str]] = []

    ecs_types = {
        "AWS::ECS::Cluster",
        "AWS::ECS::Service",
        "AWS::ECS::TaskDefinition",
    }

    for page in paginator.paginate(StackName=stack_name):
        for resource in page.get("StackResourceSummaries", []):
            resource_type = resource.get("ResourceType")
            if resource_type not in ecs_types:
                continue
            ecs_resources.append(
                {
                    "logical_id": resource.get("LogicalResourceId", ""),
                    "physical_id": resource.get("PhysicalResourceId", ""),
                    "resource_type": resource_type or "",
                }
            )

    return ecs_resources


def stack_account_id(stack: Mapping[str, Any]) -> str | None:
    stack_id = stack.get("StackId")
    if not stack_id:
        return None
    parts = str(stack_id).split(":")
    if len(parts) >= 5:
        return parts[4]
    return None


def _stack_payload_path(catalog_name: str) -> Path:
    return user_data_path("quiltx") / catalog_name / "stack.json"


def build_stack_payload(
    catalog_name: str,
    catalog_url: str,
    region: str,
    stack: Mapping[str, Any],
    log_groups: list[dict[str, str]],
    ecs_resources: list[dict[str, str]] | None = None,
    catalog_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
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
        "ecs_resources": ecs_resources or [],
        "catalog_config": catalog_config or {},
        "quiltx_version": __version__,
    }


def write_stack_payload(catalog_name: str, payload: Mapping[str, Any]) -> Path:
    """Write stack payload for a catalog."""
    output_path = _stack_payload_path(catalog_name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True))
    return output_path


def load_stack_payload(catalog_name: str) -> Mapping[str, Any] | None:
    """Load stack payload for a catalog."""
    output_path = _stack_payload_path(catalog_name)
    if not output_path.exists():
        return None
    return json.loads(output_path.read_text())


def require_stack_payload(catalog_name: str) -> Mapping[str, Any]:
    """Load stack payload for a catalog, or raise if it is missing."""
    output_path = _stack_payload_path(catalog_name)
    payload = load_stack_payload(catalog_name)
    if payload is None:
        raise FileNotFoundError(f"Missing stack payload at {output_path}")
    return payload


def format_stack_header(
    dns: str,
    payload: Mapping[str, Any] | None = None,
) -> str:
    """Format a one-line header identifying a stack and its DNS name."""
    if payload:
        stack_name = payload.get("stack_name") or "?"
        region = payload.get("region") or "?"
        account = payload.get("account_id") or "?"
        return f"Stack: {stack_name}@{region}.{account} ({dns})"
    return f"Stack: ({dns})"


def current_stack_header(ctx: "Catalog") -> str | None:
    """Return a header line for a resolved catalog context."""
    try:
        payload = ctx.payload
    except Exception:
        return None
    return format_stack_header(ctx.catalog_name, payload)


def ensure_min_version(payload: Mapping[str, Any] | None, min_version: str) -> bool:
    """Check if payload was created by a version >= min_version.

    Returns True if payload has required version or higher.
    Returns False if payload is None, missing quiltx_version, or has lower version.

    Tools should check this and prompt user to run 'quiltx stack' if False.

    Example:
        payload = load_stack_payload(catalog_name)
        if not ensure_min_version(payload, "0.1.3"):
            print("Stack data outdated. Run 'quiltx stack' to refresh.")
            return 1
    """
    if not payload:
        return False
    payload_version = payload.get("quiltx_version")
    if not payload_version:
        return False  # Old payload without version field

    # Simple version comparison (works for semantic versions like "0.1.3")
    def parse_version(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in str(v).split("."))

    try:
        return parse_version(payload_version) >= parse_version(min_version)
    except (ValueError, AttributeError):
        return False
