"""Bucket policy and notification helpers for quiltx."""

from __future__ import annotations

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
    prompt: Any = None,
    output: Any = None,
) -> tuple[Any, Any, str, str | None]:
    """Open an S3 session for *bucket*, probing other profiles if the first fails.

    Returns (session, s3_client, region, resolved_profile). Session is None if
    the user declined or no profile could access the bucket.
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

    if assume_yes:
        print(f"Retrying with profile {match}.")
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


def configure_sns_topic_policy(
    bucket: str,
    sns_topic_arn: str,
    data_account_id: str,
    control_principal_arn: str | Sequence[str],
    sns_client: Any = None,
) -> None:
    """Ensure the SNS topic policy allows S3 publish and Quilt subscribe access."""
    if sns_client is None:
        import boto3

        sns_client = boto3.client("sns")

    attributes = sns_client.get_topic_attributes(TopicArn=sns_topic_arn).get(
        "Attributes", {}
    )
    existing_policy = _parse_json_document(attributes.get("Policy"))
    publish_statement = _build_sns_topic_publish_policy_statement(
        bucket, sns_topic_arn, data_account_id
    )
    subscribe_statement = _build_sns_topic_subscribe_policy_statement(
        sns_topic_arn, control_principal_arn
    )

    if existing_policy is None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [publish_statement, subscribe_statement],
        }
    else:
        policy = dict(existing_policy)
        statements = _merge_policy_statements(
            existing_policy.get("Statement"), publish_statement
        )
        policy["Statement"] = _merge_policy_statements(statements, subscribe_statement)

    sns_client.set_topic_attributes(
        TopicArn=sns_topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(policy),
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

    Requires a cached stack payload (run ``quiltx stack`` first).

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
        raise ValueError("No cached stack metadata. Run 'quiltx stack' first.")

    control_account_id = payload.get("account_id")
    if not control_account_id:
        raise ValueError("Stack metadata missing account_id. Run 'quiltx stack' first.")
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
    topic_name = f"quilt-{bucket}-notifications"
    if len(topic_name) <= 256:
        return topic_name
    suffix = "-notifications"
    return f"quilt-{bucket[: 256 - len('quilt-') - len(suffix)]}{suffix}"


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
