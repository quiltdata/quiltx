"""Bucket policy and notification helpers for quiltx."""

from __future__ import annotations

import json
from typing import Any, Mapping

from botocore.exceptions import ClientError

QUILT_POLICY_SID = "QuiltCrossAccountAccess"
SNS_PUBLISH_POLICY_SID = "QuiltBucketNotifications"
SNS_SUBSCRIBE_POLICY_SID = "QuiltCrossAccountSNSAccess"
SNS_TOPIC_CONFIG_ID = "QuiltBucketNotifications"

QUILT_POLICY_ACTIONS = [
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
    "s3:GetBucketNotification",
    "s3:PutBucketNotification",
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
    bucket: str, control_account_id: str
) -> dict[str, Any]:
    """Build the cross-account bucket policy statement for Quilt infrastructure."""
    return {
        "Sid": QUILT_POLICY_SID,
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{control_account_id}:root"},
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
    control_principal_arn: str,
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
    sns_topic_arn: str, control_principal_arn: str
) -> dict[str, Any]:
    return {
        "Sid": SNS_SUBSCRIBE_POLICY_SID,
        "Effect": "Allow",
        "Principal": {"AWS": control_principal_arn},
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
