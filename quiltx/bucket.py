"""Bucket policy and notification helpers for quiltx."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from botocore.exceptions import ClientError

from quiltx import stack as stack_lib
from quiltx.utils import get_bucket_region


def find_profile_for_bucket(bucket: str, profiles: Sequence[str]) -> str | None:
    """Return the first profile whose GetBucketLocation succeeds for *bucket*."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    for name in profiles:
        try:
            session = boto3.Session(profile_name=name)
            session.client("s3").get_bucket_location(Bucket=bucket)
        except (ClientError, BotoCoreError):
            continue
        return name
    return None


def resolve_bucket_session(
    bucket: str,
    profile: str | None,
    *,
    assume_yes: bool,
    no_prompt: bool = False,
    prompt: Any = None,
    output: Any = None,
) -> tuple[Any, Any, str, str | None]:
    """Open an S3 session for *bucket*, probing other profiles if the first fails.

    Returns (session, s3_client, region, resolved_profile). Session is None if
    the user declined or no profile could access the bucket.

    When *no_prompt* is True, interactive prompts are suppressed; the function
    returns ``(None, None, "", profile)`` rather than asking the user.
    """
    import sys as _sys

    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    err = output if output is not None else _sys.stderr
    ask = prompt if prompt is not None else input

    session = boto3.Session(profile_name=profile)
    s3_client = session.client("s3")
    try:
        region = get_bucket_region(bucket, s3_client=s3_client)
        return session, s3_client, region, profile
    except (ClientError, BotoCoreError) as exc:
        print(
            f"Profile {profile or '<default>'} cannot access bucket {bucket}: {exc}",
            file=err,
        )

    candidates = [
        name for name in boto3.Session().available_profiles if name != (profile or "")
    ]
    match = find_profile_for_bucket(bucket, candidates)
    if match is None:
        print(f"No other configured profile can access bucket {bucket}.", file=err)
        return None, None, "", profile

    if no_prompt:
        print(
            f"Profile {profile or '<default>'} cannot access {bucket} and --no-prompt is set.",
            file=err,
        )
        return None, None, "", profile

    if assume_yes:
        print(f"Retrying with profile {match}.", file=err)
    else:
        response = ask(f"Try profile {match} instead? [y/N]: ").strip().lower()
        if response not in {"y", "yes"}:
            print("Aborted.")
            return None, None, "", profile

    new_session = boto3.Session(profile_name=match)
    new_s3 = new_session.client("s3")
    region = get_bucket_region(bucket, s3_client=new_s3)
    return new_session, new_s3, region, match


QUILT_POLICY_SID = "QuiltCrossAccountAccess"
SNS_PUBLISH_POLICY_SID = "QuiltBucketNotifications"
SNS_SUBSCRIBE_POLICY_SID = "QuiltCrossAccountSNSAccess"
SNS_TOPIC_CONFIG_ID = "QuiltBucketNotifications"

QUILT_POLICY_ACTIONS = [
    "s3:GetBucketCORS",
    "s3:GetBucketLocation",
    "s3:GetBucketNotification",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetObject",
    "s3:GetObjectAttributes",
    "s3:GetObjectTagging",
    "s3:GetObjectVersion",
    "s3:GetObjectVersionAttributes",
    "s3:GetObjectVersionTagging",
    "s3:ListBucket",
    "s3:ListBucketVersions",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:PutObject",
    "s3:PutObjectTagging",
]

BUCKET_NOTIFICATION_EVENTS = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]


class NotificationConflictError(ValueError):
    """Raised when Quilt notifications would overlap an existing destination."""


class PreparationDriftError(RuntimeError):
    """Raised when AWS state changes between preparation planning and apply."""


@dataclass(frozen=True)
class BucketPreparationPlan:
    """Exact AWS documents and secure handoff produced by bucket preparation."""

    bucket: str
    region: str
    owning_account: str
    principals: tuple[str, ...]
    sns_topic_arn: str
    bucket_policy: dict[str, Any]
    sns_policy: dict[str, Any]
    notification_configuration: dict[str, Any]
    original_bucket_policy: dict[str, Any] | None
    original_sns_policy: dict[str, Any] | None
    original_notification_configuration: dict[str, Any]
    topic_exists: bool
    bucket_policy_changed: bool
    sns_policy_changed: bool
    notification_configuration_changed: bool

    def handoff(self) -> dict[str, Any]:
        """Return the minimal non-secret handoff for the catalog operator."""
        return {
            "bucket": self.bucket,
            "region": self.region,
            "owning_account": self.owning_account,
            "principals": list(self.principals),
            "sns_topic_arn": self.sns_topic_arn,
        }


def get_bucket_policy(bucket: str, s3_client: Any = None) -> dict[str, Any] | None:
    """Return the parsed S3 bucket policy document, or None if no policy exists."""
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    try:
        response = s3_client.get_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "NoSuchBucketPolicy":
            return None
        raise

    return json.loads(response["Policy"])


def build_quilt_policy_statement(
    bucket: str,
    control_account_id: str,
    *,
    principals: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Build the cross-account bucket policy statement for Quilt infrastructure.

    When *principals* is supplied, only those principals are granted access.
    Otherwise the entire control account (``arn:aws:iam::{control_account_id}:root``)
    is used.
    """
    if principals:
        principal_value: str | list[str] = (
            list(principals) if len(principals) > 1 else principals[0]
        )
    else:
        principal_value = f"arn:aws:iam::{control_account_id}:root"
    return {
        "Sid": QUILT_POLICY_SID,
        "Effect": "Allow",
        "Principal": {"AWS": principal_value},
        "Action": list(QUILT_POLICY_ACTIONS),
        "Resource": [
            f"arn:aws:s3:::{bucket}",
            f"arn:aws:s3:::{bucket}/*",
        ],
    }


def merge_bucket_policy(
    existing: Mapping[str, Any] | None, statement: Mapping[str, Any]
) -> dict[str, Any]:
    """Merge a single statement into a bucket policy document by replacing matching Sid."""
    if existing is None:
        return {
            "Version": "2012-10-17",
            "Statement": [dict(statement)],
        }

    merged = dict(existing)
    merged["Statement"] = _merge_policy_statements(
        existing.get("Statement"), dict(statement)
    )
    return merged


def apply_bucket_policy(
    bucket: str, policy: Mapping[str, Any], s3_client: Any = None
) -> None:
    """Write the bucket policy document to S3."""
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    s3_client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def get_bucket_notification_sns(bucket: str, s3_client: Any = None) -> str | None:
    """Return the first SNS topic ARN configured for object notifications, if any."""
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    response = s3_client.get_bucket_notification_configuration(Bucket=bucket)
    for topic_config in response.get("TopicConfigurations", []):
        events = topic_config.get("Events") or []
        if _has_object_notification_event(events):
            topic_arn = topic_config.get("TopicArn")
            if topic_arn:
                return str(topic_arn)
    return None


def ensure_sns_topic(bucket: str, region: str, sns_client: Any = None) -> str:
    """Create or return the Quilt SNS topic for a bucket in the data account."""
    if sns_client is None:
        import boto3

        sns_client = boto3.client("sns", region_name=region)

    topic_name = _sns_topic_name(bucket)
    response = sns_client.create_topic(Name=topic_name)
    return str(response["TopicArn"])


def get_sns_topic_policy(
    sns_topic_arn: str, sns_client: Any = None
) -> dict[str, Any] | None:
    """Return the parsed SNS topic policy, or None when the topic has none."""
    if sns_client is None:
        import boto3

        sns_client = boto3.client("sns")

    attributes = sns_client.get_topic_attributes(TopicArn=sns_topic_arn).get(
        "Attributes", {}
    )
    return _parse_json_document(attributes.get("Policy"))


def _build_default_sns_owner_policy(
    sns_topic_arn: str, data_account_id: str
) -> dict[str, Any]:
    """Return SNS's canonical owner-access policy for a topic."""
    return {
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [
            {
                "Sid": "__default_statement_ID",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": [
                    "SNS:GetTopicAttributes",
                    "SNS:SetTopicAttributes",
                    "SNS:AddPermission",
                    "SNS:RemovePermission",
                    "SNS:DeleteTopic",
                    "SNS:Subscribe",
                    "SNS:ListSubscriptionsByTopic",
                    "SNS:Publish",
                ],
                "Resource": sns_topic_arn,
                "Condition": {"StringEquals": {"AWS:SourceOwner": data_account_id}},
            }
        ],
    }


def build_sns_topic_policy(
    existing: Mapping[str, Any] | None,
    bucket: str,
    sns_topic_arn: str,
    data_account_id: str,
    control_principal_arn: str | Sequence[str],
) -> dict[str, Any]:
    """Merge owner and Quilt statements into an SNS policy document."""
    publish_statement = _build_sns_topic_publish_policy_statement(
        bucket, sns_topic_arn, data_account_id
    )
    subscribe_statement = _build_sns_topic_subscribe_policy_statement(
        sns_topic_arn, control_principal_arn
    )
    policy = dict(
        existing
        if existing is not None
        else _build_default_sns_owner_policy(sns_topic_arn, data_account_id)
    )
    statements = _merge_policy_statements(policy.get("Statement"), publish_statement)
    policy["Statement"] = _merge_policy_statements(statements, subscribe_statement)
    return policy


def apply_sns_topic_policy(
    sns_topic_arn: str, policy: Mapping[str, Any], sns_client: Any = None
) -> None:
    """Write an SNS topic policy document."""
    if sns_client is None:
        import boto3

        sns_client = boto3.client("sns")

    sns_client.set_topic_attributes(
        TopicArn=sns_topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(policy),
    )


def configure_sns_topic_policy(
    bucket: str,
    sns_topic_arn: str,
    data_account_id: str,
    control_principal_arn: str | Sequence[str],
    sns_client: Any = None,
) -> None:
    """Ensure the SNS topic policy allows S3 publish and Quilt subscribe access."""
    existing_policy = get_sns_topic_policy(sns_topic_arn, sns_client=sns_client)
    # Preserve the legacy add-path output for backward compatibility. The
    # preparation planner uses ``None`` to model SNS's owner policy explicitly.
    policy_base = (
        existing_policy
        if existing_policy is not None
        else {"Version": "2012-10-17", "Statement": []}
    )
    policy = build_sns_topic_policy(
        policy_base,
        bucket,
        sns_topic_arn,
        data_account_id,
        control_principal_arn,
    )
    apply_sns_topic_policy(sns_topic_arn, policy, sns_client=sns_client)


def _copy_notification_configuration(response: Mapping[str, Any]) -> dict[str, Any]:
    notification_config: dict[str, Any] = {}
    for key in (
        "TopicConfigurations",
        "QueueConfigurations",
        "LambdaFunctionConfigurations",
    ):
        values = response.get(key)
        if values:
            notification_config[key] = [dict(value) for value in values]
    if "EventBridgeConfiguration" in response:
        notification_config["EventBridgeConfiguration"] = dict(
            response["EventBridgeConfiguration"]
        )
    return notification_config


def get_bucket_notification_configuration(
    bucket: str, s3_client: Any = None
) -> dict[str, Any]:
    """Return the writable portion of a bucket notification configuration."""
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")
    response = s3_client.get_bucket_notification_configuration(Bucket=bucket)
    return _copy_notification_configuration(response)


def _object_event_families(events: Sequence[str]) -> set[str]:
    families: set[str] = set()
    for event in events:
        if event.startswith("s3:ObjectCreated:"):
            families.add("ObjectCreated")
        elif event.startswith("s3:ObjectRemoved:"):
            families.add("ObjectRemoved")
    return families


def _notification_description(kind: str, config: Mapping[str, Any]) -> str:
    destination = (
        config.get("TopicArn")
        or config.get("QueueArn")
        or config.get("LambdaFunctionArn")
        or "<unknown destination>"
    )
    details = f"{kind} {config.get('Id', '<no id>')!r} ({destination})"
    if config.get("Filter"):
        details += f" with filter {config['Filter']!r}"
    return details


def _existing_notification_topic(
    notification_config: Mapping[str, Any],
) -> str | None:
    for config in notification_config.get("TopicConfigurations", []):
        if config.get("Id") == SNS_TOPIC_CONFIG_ID and config.get("TopicArn"):
            return str(config["TopicArn"])
    return None


def build_bucket_notification_configuration(
    existing: Mapping[str, Any], sns_topic_arn: str
) -> dict[str, Any]:
    """Build a safe final S3 notification document for Quilt.

    Quilt needs unfiltered create/remove notifications. Any other destination
    receiving those event families overlaps that unfiltered configuration, which
    S3 rejects. Such conflicts are reported instead of replacing user config.
    """
    notification_config = _copy_notification_configuration(existing)
    desired_families = {"ObjectCreated", "ObjectRemoved"}
    selected_topic = False

    configuration_kinds = (
        ("TopicConfigurations", "SNS topic"),
        ("QueueConfigurations", "SQS queue"),
        ("LambdaFunctionConfigurations", "Lambda function"),
    )
    for key, kind in configuration_kinds:
        updated: list[dict[str, Any]] = []
        for original in notification_config.get(key, []):
            config = dict(original)
            families = _object_event_families(config.get("Events", []))
            same_topic = key == "TopicConfigurations" and (
                config.get("TopicArn") == sns_topic_arn
                or config.get("Id") == SNS_TOPIC_CONFIG_ID
            )
            if same_topic:
                if config.get("TopicArn") not in {None, sns_topic_arn}:
                    raise NotificationConflictError(
                        f"notification id {SNS_TOPIC_CONFIG_ID!r} already points to "
                        f"{config.get('TopicArn')}; remove or rename it before preparing"
                    )
                if config.get("Filter"):
                    raise NotificationConflictError(
                        f"{_notification_description(kind, config)} cannot be reused: "
                        "Quilt requires unfiltered object-create/delete events; remove "
                        "or narrow the conflicting notification first"
                    )
                config["TopicArn"] = sns_topic_arn
                config["Events"] = [
                    event
                    for event in config.get("Events", [])
                    if not _object_event_families([event])
                ] + list(BUCKET_NOTIFICATION_EVENTS)
                selected_topic = True
            elif families & desired_families:
                raise NotificationConflictError(
                    f"{_notification_description(kind, config)} overlaps Quilt's "
                    "unfiltered object-create/delete events; remove or narrow the "
                    "conflicting notification before preparing"
                )
            updated.append(config)
        if updated:
            notification_config[key] = updated

    if not selected_topic:
        notification_config.setdefault("TopicConfigurations", []).append(
            {
                "Id": SNS_TOPIC_CONFIG_ID,
                "TopicArn": sns_topic_arn,
                "Events": list(BUCKET_NOTIFICATION_EVENTS),
            }
        )
    return notification_config


def _sns_policy_if_topic_exists(
    sns_topic_arn: str, sns_client: Any
) -> tuple[bool, dict[str, Any] | None]:
    try:
        return True, get_sns_topic_policy(sns_topic_arn, sns_client=sns_client)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"NotFound", "NotFoundException"}:
            return False, None
        raise


def _validate_retained_sns_topics(
    notification_config: Mapping[str, Any],
    selected_topic_arn: str,
    sns_client: Any,
) -> None:
    """Fail before writes when a preserved SNS notification points nowhere."""
    for config in notification_config.get("TopicConfigurations", []):
        topic_arn = config.get("TopicArn")
        if not topic_arn or topic_arn == selected_topic_arn:
            continue
        exists, _policy = _sns_policy_if_topic_exists(str(topic_arn), sns_client)
        if not exists:
            raise NotificationConflictError(
                f"preserved SNS notification {config.get('Id', '<no id>')!r} "
                f"references missing topic {topic_arn}; remove the stale "
                "notification or recreate that topic before preparing"
            )


def build_bucket_preparation_plan(
    bucket: str,
    region: str,
    owning_account: str,
    *,
    control_account_id: str | None = None,
    principals: Sequence[str] | None = None,
    s3_client: Any,
    sns_client: Any,
) -> BucketPreparationPlan:
    """Read AWS state and return the exact idempotent preparation plan."""
    principal_list = tuple(principals or ())
    if not principal_list:
        if not control_account_id:
            raise ValueError("provide --control-account-id or at least one --principal")
        principal_list = (f"arn:aws:iam::{control_account_id}:root",)

    existing_bucket_policy = get_bucket_policy(bucket, s3_client=s3_client)
    bucket_statement = build_quilt_policy_statement(
        bucket,
        control_account_id or "",
        principals=principal_list,
    )
    bucket_policy = merge_bucket_policy(existing_bucket_policy, bucket_statement)

    existing_notifications = get_bucket_notification_configuration(
        bucket, s3_client=s3_client
    )
    existing_topic_arn = _existing_notification_topic(existing_notifications)
    canonical_topic_arn = (
        f"arn:aws:sns:{region}:{owning_account}:{_sns_topic_name(bucket)}"
    )
    if existing_topic_arn is not None and existing_topic_arn != canonical_topic_arn:
        raise NotificationConflictError(
            f"bucket notification {SNS_TOPIC_CONFIG_ID!r} points to unverified topic "
            f"{existing_topic_arn}; expected the bucket-specific Quilt topic "
            f"{canonical_topic_arn}. Remove or rename the notification before "
            "preparing"
        )
    sns_topic_arn = canonical_topic_arn
    notification_configuration = build_bucket_notification_configuration(
        existing_notifications, sns_topic_arn
    )
    topic_exists, existing_sns_policy = _sns_policy_if_topic_exists(
        sns_topic_arn, sns_client
    )
    if existing_topic_arn is not None and not topic_exists:
        raise NotificationConflictError(
            f"bucket notification {SNS_TOPIC_CONFIG_ID!r} references missing SNS "
            f"topic {existing_topic_arn}; remove the stale notification or recreate "
            "that topic before preparing"
        )
    _validate_retained_sns_topics(notification_configuration, sns_topic_arn, sns_client)
    sns_policy = build_sns_topic_policy(
        existing_sns_policy,
        bucket,
        sns_topic_arn,
        owning_account,
        principal_list,
    )

    return BucketPreparationPlan(
        bucket=bucket,
        region=region,
        owning_account=owning_account,
        principals=principal_list,
        sns_topic_arn=sns_topic_arn,
        bucket_policy=bucket_policy,
        sns_policy=sns_policy,
        notification_configuration=notification_configuration,
        original_bucket_policy=existing_bucket_policy,
        original_sns_policy=existing_sns_policy,
        original_notification_configuration=existing_notifications,
        topic_exists=topic_exists,
        bucket_policy_changed=bucket_policy != existing_bucket_policy,
        sns_policy_changed=sns_policy != existing_sns_policy,
        notification_configuration_changed=(
            notification_configuration != existing_notifications
        ),
    )


def _assert_bucket_preparation_is_current(
    plan: BucketPreparationPlan, *, s3_client: Any, sns_client: Any
) -> None:
    """Optimistically verify every planned document before the first write."""
    current_bucket_policy = get_bucket_policy(plan.bucket, s3_client=s3_client)
    current_notifications = get_bucket_notification_configuration(
        plan.bucket, s3_client=s3_client
    )
    current_topic_exists, current_sns_policy = _sns_policy_if_topic_exists(
        plan.sns_topic_arn, sns_client
    )

    changed: list[str] = []
    if current_bucket_policy != plan.original_bucket_policy:
        changed.append("bucket policy")
    if current_notifications != plan.original_notification_configuration:
        changed.append("bucket notification configuration")
    if current_topic_exists != plan.topic_exists:
        changed.append("SNS topic existence")
    elif current_sns_policy != plan.original_sns_policy:
        changed.append("SNS topic policy")
    if changed:
        raise PreparationDriftError(
            "AWS state changed after planning ("
            + ", ".join(changed)
            + "); rerun bucket prepare to build a fresh plan"
        )

    _validate_retained_sns_topics(current_notifications, plan.sns_topic_arn, sns_client)


def apply_bucket_preparation(
    plan: BucketPreparationPlan, *, s3_client: Any, sns_client: Any
) -> None:
    """Apply a plan only if all AWS documents still match its baseline."""
    _assert_bucket_preparation_is_current(
        plan, s3_client=s3_client, sns_client=sns_client
    )
    if not plan.topic_exists:
        topic_arn = ensure_sns_topic(plan.bucket, plan.region, sns_client=sns_client)
        if topic_arn != plan.sns_topic_arn:
            raise ValueError(
                f"created SNS topic ARN {topic_arn!r} differs from planned "
                f"ARN {plan.sns_topic_arn!r}"
            )
    if plan.sns_policy_changed:
        apply_sns_topic_policy(
            plan.sns_topic_arn, plan.sns_policy, sns_client=sns_client
        )
    if plan.bucket_policy_changed:
        apply_bucket_policy(plan.bucket, plan.bucket_policy, s3_client=s3_client)
    if plan.notification_configuration_changed:
        s3_client.put_bucket_notification_configuration(
            Bucket=plan.bucket,
            NotificationConfiguration=plan.notification_configuration,
        )


def configure_bucket_notifications(
    bucket: str, sns_topic_arn: str, s3_client: Any = None
) -> None:
    """Merge a Quilt SNS notification destination into the bucket notification config."""
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    response = s3_client.get_bucket_notification_configuration(Bucket=bucket)
    notification_config: dict[str, Any] = {}
    for key in (
        "TopicConfigurations",
        "QueueConfigurations",
        "LambdaFunctionConfigurations",
    ):
        values = response.get(key)
        if values:
            notification_config[key] = [dict(value) for value in values]
    if "EventBridgeConfiguration" in response:
        notification_config["EventBridgeConfiguration"] = dict(
            response["EventBridgeConfiguration"]
        )

    topic_config = {
        "Id": SNS_TOPIC_CONFIG_ID,
        "TopicArn": sns_topic_arn,
        "Events": list(BUCKET_NOTIFICATION_EVENTS),
    }
    notification_config["TopicConfigurations"] = _merge_topic_configurations(
        notification_config.get("TopicConfigurations", []), topic_config
    )

    s3_client.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration=notification_config,
    )


@dataclass
class AddBucketResult:
    """Result of registering a bucket with Quilt."""

    bucket: str
    title: str
    sns_topic_arn: str
    already_registered: bool


class BucketAddError(RuntimeError):
    """Human-readable error for a GraphQL bucketAdd failure."""


def add_bucket_without_preflight(
    stack: stack_lib.Catalog,
    bucket: str,
    *,
    title: str | None = None,
) -> AddBucketResult:
    """Register a bucket by GraphQL only, without local AWS preflight/setup."""
    stack.ensure_auth()

    from quilt3 import _graphql_client
    from quilt3.admin import util

    bucket_title = title or bucket
    result = util.get_client().bucket_add(
        input=_graphql_client.BucketAddInput(
            name=bucket,
            title=bucket_title,
            sns_notification_arn=None,
        )
    )
    typename = _bucket_add_typename(result)
    if typename == "BucketAddSuccess":
        config = getattr(result, "bucket_config", None)
        return AddBucketResult(
            bucket=_field_value(config, "name", bucket),
            title=_field_value(config, "title", bucket_title),
            sns_topic_arn=_field_value(config, "sns_notification_arn", ""),
            already_registered=False,
        )
    if typename == "BucketAlreadyAdded":
        return AddBucketResult(
            bucket=bucket,
            title=bucket_title,
            sns_topic_arn="",
            already_registered=True,
        )

    raise BucketAddError(_bucket_add_error_message(result, typename))


def add_bucket(
    stack: stack_lib.Catalog,
    bucket: str,
    *,
    title: str | None = None,
    profile: str | None = None,
    principals: Sequence[str] | None = None,
) -> AddBucketResult:
    """Register an S3 bucket with the configured Quilt catalog.

    Configures cross-account bucket policy, SNS topic and policy,
    and bucket event notifications, then registers the bucket
    in the Quilt catalog.

    Requires a cached stack payload (run ``quiltx catalog stack <dns>`` first).

    Args:
        bucket: S3 bucket name.
        title: Display title in the catalog (defaults to bucket name).
        profile: AWS profile for the data account that owns the bucket.
        principals: IAM principal ARNs granted access in the bucket policy.
            Defaults to the control account root.

    Returns:
        AddBucketResult with bucket details and registration status.

    Raises:
        ValueError: If no catalog is configured or stack metadata is missing.
    """
    import boto3

    payload = stack.payload
    if not payload:
        raise ValueError(
            "No cached stack metadata. "
            "Run 'quiltx catalog stack <dns>' to populate the cache."
        )

    control_account_id = payload.get("account_id")
    if not control_account_id:
        raise ValueError(
            "Stack metadata missing account_id. "
            "Run 'quiltx catalog stack <dns>' to refresh the cache."
        )
    control_account_id = str(control_account_id)

    principal_list = list(principals) if principals else []
    sns_principal: str | list[str] = (
        principal_list if principal_list else f"arn:aws:iam::{control_account_id}:root"
    )

    bucket_title = title or bucket

    # Check if already registered
    existing = stack.admin.buckets.get(bucket)
    if existing is not None:
        return AddBucketResult(
            bucket=bucket,
            title=getattr(existing, "title", bucket_title),
            sns_topic_arn=getattr(existing, "sns_notification_arn", "") or "",
            already_registered=True,
        )

    session = boto3.Session(profile_name=profile)
    s3_client = session.client("s3")
    bucket_region = get_bucket_region(bucket, s3_client=s3_client)
    sns_client = session.client("sns", region_name=bucket_region)
    data_account_id = str(session.client("sts").get_caller_identity()["Account"])

    existing_policy = get_bucket_policy(bucket, s3_client=s3_client)
    statement = build_quilt_policy_statement(
        bucket, control_account_id, principals=principal_list or None
    )
    merged = merge_bucket_policy(existing_policy, statement)
    apply_bucket_policy(bucket, merged, s3_client=s3_client)

    # SNS topic
    sns_topic_arn = get_bucket_notification_sns(bucket, s3_client=s3_client)
    if sns_topic_arn is None:
        sns_topic_arn = ensure_sns_topic(bucket, bucket_region, sns_client=sns_client)

    configure_sns_topic_policy(
        bucket,
        sns_topic_arn,
        data_account_id,
        sns_principal,
        sns_client=sns_client,
    )

    # Bucket notifications
    configure_bucket_notifications(bucket, sns_topic_arn, s3_client=s3_client)

    # Register in Quilt catalog
    stack.admin.buckets.add(
        name=bucket,
        title=bucket_title,
        sns_notification_arn=sns_topic_arn,
    )

    return AddBucketResult(
        bucket=bucket,
        title=bucket_title,
        sns_topic_arn=sns_topic_arn,
        already_registered=False,
    )


def _bucket_add_typename(result: Any) -> str:
    if isinstance(result, Mapping):
        value = result.get("__typename") or result.get("typename__")
        return str(value or "")
    return str(
        getattr(result, "typename__", None)
        or getattr(result, "__typename", None)
        or result.__class__.__name__
    )


def _field_value(source: Any, field: str, default: str) -> str:
    if source is None:
        return default
    if isinstance(source, Mapping):
        return str(source.get(field) or default)
    return str(getattr(source, field, None) or default)


def _bucket_add_error_message(result: Any, typename: str) -> str:
    if typename == "BucketDoesNotExist":
        return (
            "BucketDoesNotExist: The stack cannot access this bucket; check "
            "the stack's IAM role or the bucket's public-access settings."
        )
    if typename == "InsufficientPermissions":
        detail = _field_value(result, "message", "")
        if detail:
            return f"InsufficientPermissions: {detail}"
        return "InsufficientPermissions: stack lacks required access to this bucket."
    if typename in {
        "NotificationConfigurationError",
        "NotificationTopicNotFound",
        "SnsInvalid",
        "SubscriptionInvalid",
        "BucketFileExtensionsToIndexInvalid",
        "BucketIndexContentBytesInvalid",
    }:
        detail = _field_value(result, "message", "")
        return f"{typename}: {detail}" if detail else typename
    return f"bucketAdd returned {typename or 'an unknown error'}: {result}"


def _merge_policy_statements(
    existing_statements: Any, statement: dict[str, Any]
) -> list[dict[str, Any]]:
    if existing_statements is None:
        return [statement]
    if isinstance(existing_statements, Mapping):
        statements = [dict(existing_statements)]
    else:
        statements = [
            dict(item) for item in existing_statements if isinstance(item, Mapping)
        ]

    sid = statement.get("Sid")
    replaced = False
    for idx, existing in enumerate(statements):
        if existing.get("Sid") == sid:
            statements[idx] = statement
            replaced = True
            break
    if not replaced:
        statements.append(statement)
    return statements


def _has_object_notification_event(events: list[str]) -> bool:
    return any(
        event.startswith("s3:ObjectCreated:") or event.startswith("s3:ObjectRemoved:")
        for event in events
    )


def _sns_topic_name(bucket: str) -> str:
    prefix = "quilt-"
    suffix = "-notifications"
    normalized_bucket = "".join(
        char if char.isascii() and (char.isalnum() or char in "_-") else "-"
        for char in bucket
    )
    topic_name = f"{prefix}{normalized_bucket}{suffix}"
    if topic_name == f"{prefix}{bucket}{suffix}" and len(topic_name) <= 256:
        return topic_name

    # S3 bucket names cannot contain underscores, so transformed names occupy a
    # namespace that no unchanged bucket can produce. The digest also separates
    # different bucket names that normalize to the same SNS-safe spelling.
    transformed_prefix = "quilt-x_"
    digest = hashlib.sha256(bucket.encode()).hexdigest()[:12]
    unique_suffix = f"-{digest}{suffix}"
    max_bucket_length = 256 - len(transformed_prefix) - len(unique_suffix)
    return f"{transformed_prefix}{normalized_bucket[:max_bucket_length]}{unique_suffix}"


def _build_sns_topic_publish_policy_statement(
    bucket: str, sns_topic_arn: str, data_account_id: str
) -> dict[str, Any]:
    return {
        "Sid": SNS_PUBLISH_POLICY_SID,
        "Effect": "Allow",
        "Principal": {"Service": "s3.amazonaws.com"},
        "Action": "sns:Publish",
        "Resource": sns_topic_arn,
        "Condition": {
            "ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"},
            "StringEquals": {"aws:SourceAccount": data_account_id},
        },
    }


def _build_sns_topic_subscribe_policy_statement(
    sns_topic_arn: str, control_principals: str | Sequence[str]
) -> dict[str, Any]:
    if isinstance(control_principals, str):
        principal_value: str | list[str] = control_principals
    else:
        principals = list(control_principals)
        principal_value = principals[0] if len(principals) == 1 else principals
    return {
        "Sid": SNS_SUBSCRIBE_POLICY_SID,
        "Effect": "Allow",
        "Principal": {"AWS": principal_value},
        "Action": [
            "sns:GetTopicAttributes",
            "sns:Subscribe",
        ],
        "Resource": sns_topic_arn,
    }


def _parse_json_document(raw_value: Any) -> dict[str, Any] | None:
    if not raw_value:
        return None
    if isinstance(raw_value, Mapping):
        return dict(raw_value)
    return json.loads(str(raw_value))


def _merge_topic_configurations(
    existing_configs: list[dict[str, Any]], topic_config: dict[str, Any]
) -> list[dict[str, Any]]:
    merged = [dict(config) for config in existing_configs]
    for idx, config in enumerate(merged):
        if (
            config.get("Id") == topic_config["Id"]
            or config.get("TopicArn") == topic_config["TopicArn"]
        ):
            merged[idx] = dict(topic_config)
            return merged
    merged.append(dict(topic_config))
    return merged
