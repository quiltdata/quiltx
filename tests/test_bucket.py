"""Tests for bucket helpers and the bucket tool."""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
from dataclasses import dataclass, replace
from types import ModuleType, SimpleNamespace
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from quiltx import bucket as bucket_lib
from quiltx.bucket import AddBucketResult, add_bucket
from quiltx.tools import bucket as bucket_tool

from tests.conftest import make_fake_catalog


def _client(service_name: str, region_name: str = "us-east-1"):
    return boto3.client(
        service_name,
        region_name=region_name,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
    )


def _install_stack_context(monkeypatch, catalog_name: str = "demo") -> None:
    cat = make_fake_catalog(catalog_name)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: cat,
    )


def test_build_quilt_policy_statement() -> None:
    statement = bucket_lib.build_quilt_policy_statement("demo-bucket", "123456789012")
    assert statement["Sid"] == "QuiltCrossAccountAccess"
    assert statement["Principal"] == {"AWS": "arn:aws:iam::123456789012:root"}
    assert statement["Resource"] == [
        "arn:aws:s3:::demo-bucket",
        "arn:aws:s3:::demo-bucket/*",
    ]
    assert statement["Action"] == bucket_lib.QUILT_POLICY_ACTIONS
    assert len(statement["Action"]) == 17


def test_merge_bucket_policy_no_existing() -> None:
    statement = bucket_lib.build_quilt_policy_statement("bucket", "123456789012")
    policy = bucket_lib.merge_bucket_policy(None, statement)
    assert policy == {
        "Version": "2012-10-17",
        "Statement": [statement],
    }


def test_merge_bucket_policy_appends() -> None:
    existing = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Existing", "Effect": "Allow"}],
    }
    statement = bucket_lib.build_quilt_policy_statement("bucket", "123456789012")
    policy = bucket_lib.merge_bucket_policy(existing, statement)
    assert policy["Statement"] == [
        {"Sid": "Existing", "Effect": "Allow"},
        statement,
    ]


def test_merge_bucket_policy_replaces_duplicate_sid() -> None:
    existing = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "QuiltCrossAccountAccess",
                "Effect": "Deny",
            }
        ],
    }
    statement = bucket_lib.build_quilt_policy_statement("bucket", "123456789012")
    policy = bucket_lib.merge_bucket_policy(existing, statement)
    assert policy["Statement"] == [statement]


def test_get_bucket_policy_empty() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        service_message="No bucket policy",
        expected_params={"Bucket": "bucket"},
    )
    stubber.activate()

    assert bucket_lib.get_bucket_policy("bucket", s3_client=client) is None

    stubber.deactivate()


def test_get_bucket_policy_existing() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    policy = {"Version": "2012-10-17", "Statement": [{"Sid": "Existing"}]}
    stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(policy)},
        {"Bucket": "bucket"},
    )
    stubber.activate()

    assert bucket_lib.get_bucket_policy("bucket", s3_client=client) == policy

    stubber.deactivate()


def test_apply_bucket_policy() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    policy = {"Version": "2012-10-17", "Statement": []}
    stubber.add_response(
        "put_bucket_policy",
        {},
        {"Bucket": "bucket", "Policy": json.dumps(policy)},
    )
    stubber.activate()

    bucket_lib.apply_bucket_policy("bucket", policy, s3_client=client)

    stubber.deactivate()


def test_get_bucket_notification_sns_exists() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "existing",
                    "TopicArn": "arn:aws:sns:us-east-1:123456789012:topic",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        },
        {"Bucket": "bucket"},
    )
    stubber.activate()

    assert (
        bucket_lib.get_bucket_notification_sns("bucket", s3_client=client)
        == "arn:aws:sns:us-east-1:123456789012:topic"
    )

    stubber.deactivate()


def test_get_bucket_notification_sns_none() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    stubber.add_response(
        "get_bucket_notification_configuration",
        {"QueueConfigurations": []},
        {"Bucket": "bucket"},
    )
    stubber.activate()

    assert bucket_lib.get_bucket_notification_sns("bucket", s3_client=client) is None

    stubber.deactivate()


def test_ensure_sns_topic_creates() -> None:
    client = _client("sns")
    stubber = Stubber(client)
    stubber.add_response(
        "create_topic",
        {"TopicArn": "arn:aws:sns:us-east-1:123456789012:quilt-bucket-notifications"},
        {"Name": "quilt-bucket-notifications"},
    )
    stubber.activate()

    assert (
        bucket_lib.ensure_sns_topic("bucket", "us-east-1", sns_client=client)
        == "arn:aws:sns:us-east-1:123456789012:quilt-bucket-notifications"
    )

    stubber.deactivate()


def test_ensure_sns_topic_fails_hard() -> None:
    client = _client("sns")
    stubber = Stubber(client)
    stubber.add_client_error(
        "create_topic",
        service_error_code="AuthorizationError",
        service_message="denied",
        expected_params={"Name": "quilt-bucket-notifications"},
    )
    stubber.activate()

    try:
        bucket_lib.ensure_sns_topic("bucket", "us-east-1", sns_client=client)
    except Exception as exc:
        assert "CreateTopic" in str(exc)
    else:
        raise AssertionError("expected create_topic failure")
    finally:
        stubber.deactivate()


def test_sns_topic_name_normalizes_dotted_bucket_with_collision_hash() -> None:
    dotted_bucket = "example.data.bucket"
    first = bucket_lib._sns_topic_name(dotted_bucket)
    digest = hashlib.sha256(dotted_bucket.encode()).hexdigest()[:12]
    adversarial = bucket_lib._sns_topic_name(f"example-data-bucket-{digest}")

    assert "." not in first
    assert first.startswith("quilt-x_example-data-bucket-")
    assert first.endswith("-notifications")
    assert len(first) <= 256
    assert first != adversarial


def test_build_sns_topic_policy_preserves_owner_access() -> None:
    topic_arn = "arn:aws:sns:us-east-1:111122223333:topic"

    policy = bucket_lib.build_sns_topic_policy(
        None,
        "bucket",
        topic_arn,
        "111122223333",
        ["arn:aws:iam::123456789012:root"],
    )

    owner_statement = policy["Statement"][0]
    assert owner_statement["Sid"] == "__default_statement_ID"
    assert owner_statement["Action"] == [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:AddPermission",
        "SNS:RemovePermission",
        "SNS:DeleteTopic",
        "SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Publish",
    ]
    assert owner_statement["Condition"] == {
        "StringEquals": {"AWS:SourceOwner": "111122223333"}
    }
    assert [statement["Sid"] for statement in policy["Statement"]] == [
        "__default_statement_ID",
        "QuiltBucketNotifications",
        "QuiltCrossAccountSNSAccess",
    ]


def test_configure_sns_topic_policy_creates_or_merges() -> None:
    client = _client("sns")
    stubber = Stubber(client)
    topic_arn = "arn:aws:sns:us-east-1:123456789012:topic"
    existing_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Existing", "Effect": "Allow"}],
    }
    expected_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Existing", "Effect": "Allow"},
            {
                "Sid": "QuiltBucketNotifications",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic_arn,
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": "arn:aws:s3:::bucket"},
                    "StringEquals": {"aws:SourceAccount": "123456789012"},
                },
            },
            {
                "Sid": "QuiltCrossAccountSNSAccess",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/quilt-registry"},
                "Action": [
                    "sns:GetTopicAttributes",
                    "sns:Subscribe",
                ],
                "Resource": topic_arn,
            },
        ],
    }
    stubber.add_response(
        "get_topic_attributes",
        {"Attributes": {"Policy": json.dumps(existing_policy)}},
        {"TopicArn": topic_arn},
    )
    stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
            "AttributeName": "Policy",
            "AttributeValue": json.dumps(expected_policy),
        },
    )
    stubber.activate()

    bucket_lib.configure_sns_topic_policy(
        "bucket",
        topic_arn,
        "123456789012",
        "arn:aws:iam::123456789012:role/quilt-registry",
        sns_client=client,
    )

    stubber.deactivate()


def test_configure_notifications_merges() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    existing = {
        "LambdaFunctionConfigurations": [
            {
                "Id": "lambda",
                "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:f",
                "Events": ["s3:ReducedRedundancyLostObject"],
            }
        ],
        "QueueConfigurations": [
            {
                "Id": "queue",
                "QueueArn": "arn:aws:sqs:us-east-1:123456789012:q",
                "Events": ["s3:ObjectRestore:Completed"],
            }
        ],
    }
    topic_arn = "arn:aws:sns:us-east-1:123456789012:topic"
    expected = bucket_lib.build_bucket_notification_configuration(existing, topic_arn)
    stubber.add_response(
        "get_bucket_notification_configuration",
        existing,
        {"Bucket": "bucket"},
    )
    stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {"Bucket": "bucket", "NotificationConfiguration": expected},
    )
    stubber.activate()

    bucket_lib.configure_bucket_notifications("bucket", topic_arn, s3_client=client)

    stubber.deactivate()


def test_build_prepare_notifications_preserves_compatible_destinations() -> None:
    existing = {
        "TopicConfigurations": [
            {
                "Id": "archive-topic",
                "TopicArn": "arn:aws:sns:us-east-1:111122223333:archive",
                "Events": ["s3:ObjectRestore:Completed"],
            }
        ],
        "QueueConfigurations": [
            {
                "Id": "archive-queue",
                "QueueArn": "arn:aws:sqs:us-east-1:111122223333:archive",
                "Events": ["s3:ObjectRestore:Delete"],
            }
        ],
        "LambdaFunctionConfigurations": [
            {
                "Id": "archive-lambda",
                "LambdaFunctionArn": (
                    "arn:aws:lambda:us-east-1:111122223333:function:archive"
                ),
                "Events": ["s3:ReducedRedundancyLostObject"],
            }
        ],
        "EventBridgeConfiguration": {},
    }
    topic_arn = "arn:aws:sns:us-east-1:111122223333:quilt-bucket-notifications"

    result = bucket_lib.build_bucket_notification_configuration(existing, topic_arn)

    assert result["TopicConfigurations"][:-1] == existing["TopicConfigurations"]
    assert result["TopicConfigurations"][-1] == {
        "Id": "QuiltBucketNotifications",
        "TopicArn": topic_arn,
        "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
    }
    assert result["QueueConfigurations"] == existing["QueueConfigurations"]
    assert (
        result["LambdaFunctionConfigurations"]
        == existing["LambdaFunctionConfigurations"]
    )
    assert result["EventBridgeConfiguration"] == {}


@pytest.mark.parametrize(
    ("key", "arn_key", "arn"),
    [
        (
            "TopicConfigurations",
            "TopicArn",
            "arn:aws:sns:us-east-1:111122223333:other",
        ),
        (
            "QueueConfigurations",
            "QueueArn",
            "arn:aws:sqs:us-east-1:111122223333:queue",
        ),
        (
            "LambdaFunctionConfigurations",
            "LambdaFunctionArn",
            "arn:aws:lambda:us-east-1:111122223333:function:handler",
        ),
    ],
)
def test_build_prepare_notifications_rejects_object_event_overlap(
    key: str, arn_key: str, arn: str
) -> None:
    existing = {
        key: [
            {
                "Id": "existing",
                arn_key: arn,
                "Events": ["s3:ObjectCreated:Put"],
                "Filter": {
                    "Key": {"FilterRules": [{"Name": "prefix", "Value": "uploads/"}]}
                },
            }
        ]
    }

    with pytest.raises(bucket_lib.NotificationConflictError) as exc_info:
        bucket_lib.build_bucket_notification_configuration(
            existing,
            "arn:aws:sns:us-east-1:111122223333:quilt-bucket-notifications",
        )

    message = str(exc_info.value)
    assert "overlaps" in message
    assert "remove or narrow" in message
    assert "uploads/" in message


def test_prepare_plan_rejects_unrelated_object_topic_instead_of_adopting() -> None:
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "audit",
                    "TopicArn": "arn:aws:sns:us-west-2:111122223333:audit",
                    "Events": ["s3:ObjectCreated:Put"],
                }
            ]
        },
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    sns_stubber.activate()

    with pytest.raises(bucket_lib.NotificationConflictError, match="audit"):
        bucket_lib.build_bucket_preparation_plan(
            "bucket",
            "us-west-2",
            "111122223333",
            control_account_id="123456789012",
            s3_client=s3_client,
            sns_client=sns_client,
        )

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()


def test_prepare_plan_rejects_unverified_quilt_notification_topic() -> None:
    unverified_topic = "arn:aws:sns:us-west-2:111122223333:unrelated"
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "QuiltBucketNotifications",
                    "TopicArn": unverified_topic,
                    "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                }
            ]
        },
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()
    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    sns_stubber.activate()

    with pytest.raises(bucket_lib.NotificationConflictError, match="unverified topic"):
        bucket_lib.build_bucket_preparation_plan(
            "bucket",
            "us-west-2",
            "111122223333",
            control_account_id="123456789012",
            s3_client=s3_client,
            sns_client=sns_client,
        )

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()


def test_prepare_plan_rejects_stale_quilt_topic_before_writes() -> None:
    stale_topic = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "QuiltBucketNotifications",
                    "TopicArn": stale_topic,
                    "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                }
            ]
        },
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    sns_stubber.add_client_error(
        "get_topic_attributes",
        service_error_code="NotFound",
        expected_params={"TopicArn": stale_topic},
    )
    sns_stubber.activate()

    with pytest.raises(bucket_lib.NotificationConflictError, match="missing SNS topic"):
        bucket_lib.build_bucket_preparation_plan(
            "bucket",
            "us-west-2",
            "111122223333",
            control_account_id="123456789012",
            s3_client=s3_client,
            sns_client=sns_client,
        )

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()


def test_prepare_plan_rejects_stale_preserved_topic_before_writes() -> None:
    archive_topic = "arn:aws:sns:us-west-2:111122223333:archive"
    planned_topic = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "archive",
                    "TopicArn": archive_topic,
                    "Events": ["s3:ObjectRestore:Completed"],
                }
            ]
        },
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    sns_stubber.add_client_error(
        "get_topic_attributes",
        service_error_code="NotFound",
        expected_params={"TopicArn": planned_topic},
    )
    sns_stubber.add_client_error(
        "get_topic_attributes",
        service_error_code="NotFound",
        expected_params={"TopicArn": archive_topic},
    )
    sns_stubber.activate()

    with pytest.raises(bucket_lib.NotificationConflictError, match="archive"):
        bucket_lib.build_bucket_preparation_plan(
            "bucket",
            "us-west-2",
            "111122223333",
            control_account_id="123456789012",
            s3_client=s3_client,
            sns_client=sns_client,
        )

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()


def test_bucket_preparation_is_idempotent_across_new_and_existing_topic() -> None:
    bucket = "bucket"
    region = "us-west-2"
    owning_account = "111122223333"
    control_account = "123456789012"
    principal = f"arn:aws:iam::{control_account}:root"
    topic_arn = f"arn:aws:sns:{region}:{owning_account}:quilt-bucket-notifications"
    existing_bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Existing", "Effect": "Allow"}],
    }
    final_bucket_policy = bucket_lib.merge_bucket_policy(
        existing_bucket_policy,
        bucket_lib.build_quilt_policy_statement(
            bucket, control_account, principals=[principal]
        ),
    )
    final_sns_policy = bucket_lib.build_sns_topic_policy(
        None, bucket, topic_arn, owning_account, [principal]
    )
    final_notifications = bucket_lib.build_bucket_notification_configuration(
        {"EventBridgeConfiguration": {}}, topic_arn
    )

    s3_client = _client("s3", region_name=region)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(existing_bucket_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {"EventBridgeConfiguration": {}},
        {"Bucket": bucket},
    )
    # Revalidation immediately before the first apply.
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(existing_bucket_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {"EventBridgeConfiguration": {}},
        {"Bucket": bucket},
    )
    # Recheck immediately before each write.
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(existing_bucket_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {"Bucket": bucket, "Policy": json.dumps(final_bucket_policy)},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {"EventBridgeConfiguration": {}},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {"Bucket": bucket, "NotificationConfiguration": final_notifications},
    )
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(final_bucket_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        final_notifications,
        {"Bucket": bucket},
    )
    # Revalidation before the converged no-op apply.
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(final_bucket_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        final_notifications,
        {"Bucket": bucket},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name=region)
    sns_stubber = Stubber(sns_client)
    sns_stubber.add_client_error(
        "get_topic_attributes",
        service_error_code="NotFound",
        service_message="topic does not exist",
        expected_params={"TopicArn": topic_arn},
    )
    # Revalidation confirms the planned topic is still absent.
    sns_stubber.add_client_error(
        "get_topic_attributes",
        service_error_code="NotFound",
        service_message="topic does not exist",
        expected_params={"TopicArn": topic_arn},
    )
    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": topic_arn},
        {"Name": "quilt-bucket-notifications"},
    )
    # Recheck the just-created topic still carries only the default owner policy.
    sns_stubber.add_response(
        "get_topic_attributes",
        {
            "Attributes": {
                "Policy": json.dumps(
                    bucket_lib._build_default_sns_owner_policy(
                        topic_arn, owning_account
                    )
                )
            }
        },
        {"TopicArn": topic_arn},
    )
    sns_stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
            "AttributeName": "Policy",
            "AttributeValue": json.dumps(final_sns_policy),
        },
    )
    sns_stubber.add_response(
        "get_topic_attributes",
        {"Attributes": {"Policy": json.dumps(final_sns_policy)}},
        {"TopicArn": topic_arn},
    )
    # Revalidation before the converged no-op apply.
    sns_stubber.add_response(
        "get_topic_attributes",
        {"Attributes": {"Policy": json.dumps(final_sns_policy)}},
        {"TopicArn": topic_arn},
    )
    sns_stubber.activate()

    first = bucket_lib.build_bucket_preparation_plan(
        bucket,
        region,
        owning_account,
        control_account_id=control_account,
        s3_client=s3_client,
        sns_client=sns_client,
    )
    assert first.topic_exists is False
    bucket_lib.apply_bucket_preparation(
        first, s3_client=s3_client, sns_client=sns_client
    )

    second = bucket_lib.build_bucket_preparation_plan(
        bucket,
        region,
        owning_account,
        control_account_id=control_account,
        s3_client=s3_client,
        sns_client=sns_client,
    )
    assert second.topic_exists is True
    assert second.bucket_policy_changed is False
    assert second.sns_policy_changed is False
    assert second.notification_configuration_changed is False
    assert second.bucket_policy == first.bucket_policy
    assert second.sns_policy == first.sns_policy
    assert second.notification_configuration == first.notification_configuration
    bucket_lib.apply_bucket_preparation(
        second, s3_client=s3_client, sns_client=sns_client
    )

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()


def test_bucket_preparation_rejects_drift_before_any_write() -> None:
    bucket = "bucket"
    region = "us-west-2"
    topic_arn = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    baseline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Existing", "Effect": "Allow"}],
    }
    changed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Existing", "Effect": "Allow"},
            {"Sid": "ConcurrentWriter", "Effect": "Deny"},
        ],
    }

    s3_client = _client("s3", region_name=region)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(baseline_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration", {}, {"Bucket": bucket}
    )
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(changed_policy)},
        {"Bucket": bucket},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration", {}, {"Bucket": bucket}
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name=region)
    sns_stubber = Stubber(sns_client)
    for _ in range(2):
        sns_stubber.add_client_error(
            "get_topic_attributes",
            service_error_code="NotFound",
            expected_params={"TopicArn": topic_arn},
        )
    sns_stubber.activate()

    plan = bucket_lib.build_bucket_preparation_plan(
        bucket,
        region,
        "111122223333",
        control_account_id="123456789012",
        s3_client=s3_client,
        sns_client=sns_client,
    )
    with pytest.raises(bucket_lib.PreparationDriftError, match="bucket policy"):
        bucket_lib.apply_bucket_preparation(
            plan, s3_client=s3_client, sns_client=sns_client
        )

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()


@dataclass
class FakeBucket:
    name: str
    title: str
    sns_notification_arn: str | None = None
    prefixes: list[str] | None = None


class FakeSession:
    def __init__(
        self, s3_client, sns_client, sts_client, sqs_client=None, lambda_client=None
    ) -> None:
        self._s3_client = s3_client
        self._sns_client = sns_client
        self._sts_client = sts_client
        self._sqs_client = sqs_client
        self._lambda_client = lambda_client
        self.profile_name = None

    def client(self, service_name: str, region_name: str | None = None):
        if service_name == "s3":
            return self._s3_client
        if service_name == "sns":
            assert region_name == "us-west-2"
            return self._sns_client
        if service_name == "sqs":
            assert region_name == "us-west-2"
            return self._sqs_client if self._sqs_client is not None else object()
        if service_name == "lambda":
            assert region_name == "us-west-2"
            return self._lambda_client if self._lambda_client is not None else object()
        if service_name == "sts":
            return self._sts_client
        raise AssertionError(f"unexpected service: {service_name}")


def _fake_bucket_preparation_plan() -> bucket_lib.BucketPreparationPlan:
    return bucket_lib.BucketPreparationPlan(
        bucket="bucket",
        region="us-west-2",
        owning_account="111122223333",
        principals=("arn:aws:iam::123456789012:root",),
        sns_topic_arn=("arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"),
        bucket_policy={"Version": "2012-10-17", "Statement": [{"Sid": "bucket"}]},
        sns_policy={"Version": "2012-10-17", "Statement": [{"Sid": "sns"}]},
        notification_configuration={"TopicConfigurations": [{"Id": "notification"}]},
        original_bucket_policy=None,
        original_sns_policy=None,
        original_notification_configuration={},
        topic_exists=False,
        bucket_policy_changed=True,
        sns_policy_changed=True,
        notification_configuration_changed=True,
    )


def _install_prepare_fakes(monkeypatch, plan: bucket_lib.BucketPreparationPlan) -> None:
    session = SimpleNamespace(client=lambda service_name, region_name=None: object())
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "resolve_bucket_session",
        lambda *args, **kwargs: (session, object(), "us-west-2", None),
    )
    monkeypatch.setattr(
        bucket_tool, "_get_session_account_id", lambda _session: "111122223333"
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "build_bucket_preparation_plan",
        lambda *args, **kwargs: plan,
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("prepare must not resolve or authenticate a catalog")
        ),
    )


def test_prepare_dry_run_prints_exact_documents_without_writes(
    monkeypatch, capsys
) -> None:
    plan = _fake_bucket_preparation_plan()
    _install_prepare_fakes(monkeypatch, plan)
    documents: list[dict[str, Any]] = []
    monkeypatch.setattr(
        bucket_tool,
        "_print_json",
        lambda _console, document: documents.append(dict(document)),
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "apply_bucket_preparation",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dry-run must not write AWS state")
        ),
    )

    result = bucket_tool.main(
        ["prepare", "bucket", "--control-account-id", "123456789012", "--dry-run"]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "Final bucket policy:" in output
    assert "Final SNS topic policy:" in output
    assert "Final bucket notification configuration:" in output
    assert documents == [
        plan.bucket_policy,
        plan.sns_policy,
        plan.notification_configuration,
    ]


def test_prepare_json_is_minimal_and_uses_no_catalog(monkeypatch, capsys) -> None:
    plan = _fake_bucket_preparation_plan()
    _install_prepare_fakes(monkeypatch, plan)
    applied: list[bucket_lib.BucketPreparationPlan] = []
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "apply_bucket_preparation",
        lambda candidate, **kwargs: applied.append(candidate),
    )

    result = bucket_tool.main(
        ["prepare", "bucket", "--control-account-id", "123456789012", "--json", "--yes"]
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out) == {
        "bucket": "bucket",
        "region": "us-west-2",
        "owning_account": "111122223333",
        "principals": ["arn:aws:iam::123456789012:root"],
        "sns_topic_arn": (
            "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
        ),
    }
    assert applied == [plan]


def test_prepare_json_profile_failure_keeps_stdout_clean(monkeypatch, capsys) -> None:
    seen: dict[str, Any] = {}

    def fail_resolve(*args, **kwargs):
        seen.update(kwargs)
        print("profile cannot access bucket", file=kwargs["output"])
        return None, None, "", "requested"

    monkeypatch.setattr(bucket_tool.bucket_lib, "resolve_bucket_session", fail_resolve)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("prepare must not resolve a catalog")
        ),
    )

    result = bucket_tool.main(
        [
            "prepare",
            "bucket",
            "--profile",
            "requested",
            "--control-account-id",
            "123456789012",
            "--json",
            "--yes",
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert "profile cannot access bucket" in captured.err
    assert seen["no_prompt"] is True
    assert seen["output"] is sys.stderr


def test_prepare_json_default_profile_fallback_keeps_json_stdout(
    monkeypatch, capsys
) -> None:
    from botocore.exceptions import ClientError

    plan = _fake_bucket_preparation_plan()

    class FakeS3:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def get_bucket_location(self, Bucket: str) -> dict[str, Any]:
            if self.profile == "prod":
                return {"LocationConstraint": "us-west-2"}
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "GetBucketLocation",
            )

    class FallbackSession:
        available_profiles = ["prod"]

        def __init__(self, profile_name: str | None = None) -> None:
            self.profile_name = profile_name or ""

        def client(self, service: str, region_name: str | None = None):
            if service == "s3":
                return FakeS3(self.profile_name)
            if service in {"sns", "sqs", "lambda"}:
                assert region_name == "us-west-2"
                return object()
            raise AssertionError(f"unexpected service {service}")

    monkeypatch.setattr(bucket_tool.boto3, "Session", FallbackSession)
    monkeypatch.setattr(
        bucket_tool, "_get_session_account_id", lambda _session: "111122223333"
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "build_bucket_preparation_plan",
        lambda *args, **kwargs: plan,
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib, "apply_bucket_preparation", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("prepare must not resolve a catalog")
        ),
    )

    result = bucket_tool.main(
        [
            "prepare",
            "bucket",
            "--control-account-id",
            "123456789012",
            "--json",
            "--yes",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert json.loads(captured.out) == plan.handoff()
    assert "Retrying with profile prod." in captured.err


class FakeQuiltBucket:
    def __init__(self, uri: str) -> None:
        self.uri = uri

    def ls(self):
        return iter(["file.txt"])

    def search(self, query, limit=10):
        return [{"_source": {"key": "file.txt"}}]


def _install_fake_quilt3(monkeypatch, *, get_result=None, listed=None, add_calls=None):
    bucket_list = list(listed or [])
    if get_result is not None and listed is None:
        bucket_list.append(get_result)

    admin_buckets = SimpleNamespace()
    admin_buckets.get = lambda name: get_result
    admin_buckets.list = lambda: list(bucket_list)

    def add(**kwargs):
        if add_calls is not None:
            add_calls.append(kwargs)
        bucket = FakeBucket(
            kwargs["name"], kwargs["title"], kwargs.get("sns_notification_arn"), []
        )
        bucket_list.append(bucket)
        return bucket

    admin_buckets.add = add

    admin_module = ModuleType("quilt3.admin")
    admin_module.buckets = admin_buckets
    admin_module.policies = SimpleNamespace()
    admin_module.roles = SimpleNamespace()
    admin_module.sso_config = SimpleNamespace()
    admin_module.users = SimpleNamespace()
    quilt3_module = ModuleType("quilt3")
    quilt3_module.admin = admin_module
    quilt3_module.Bucket = FakeQuiltBucket
    monkeypatch.setitem(sys.modules, "quilt3", quilt3_module)
    monkeypatch.setitem(sys.modules, "quilt3.admin", admin_module)


def test_add_dry_run(monkeypatch, capsys) -> None:
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps({"Version": "2012-10-17", "Statement": []})},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {"TopicConfigurations": []},
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    sns_stubber.add_client_error(
        "get_topic_attributes",
        service_error_code="NotFound",
        expected_params={
            "TopicArn": (
                "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
            )
        },
    )
    sns_stubber.activate()

    sts_client = _client("sts", region_name="us-west-2")
    sts_stubber = Stubber(sts_client)
    sts_stubber.add_response(
        "get_caller_identity",
        {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:user/test",
            "UserId": "test",
        },
        {},
    )
    sts_stubber.activate()

    session = FakeSession(s3_client, sns_client, sts_client)
    monkeypatch.setattr(bucket_tool.boto3, "Session", lambda profile_name=None: session)
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {
            "account_id": "123456789012",
            "stack_name": "quilt-demo-stack",
            "region": "us-east-1",
            "outputs": [
                {
                    "OutputKey": "RegistryRoleARN",
                    "OutputValue": "arn:aws:iam::123456789012:role/quilt-registry",
                }
            ],
        },
    )
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])

    assert bucket_tool.main(["add", "bucket", "--dry-run"]) == 0
    captured = capsys.readouterr()
    assert "Bucket add dry-run" in captured.out
    assert "Resource" in captured.out
    assert "Account" in captured.out
    assert "Region" in captured.out
    assert "Source" in captured.out
    assert "demo" in captured.out
    assert "cached stack.json" in captured.out
    assert "s3://bucket" in captured.out
    assert "quilt-demo-stack" in captured.out
    assert "arn:aws:iam::123456789012:root" in captured.out
    assert "account root (default)" in captured.out
    assert "123456789012" in captured.out
    assert "111122223333" in captured.out
    assert "us-west-2" in captured.out
    assert "AWS profile <default>" in captured.out
    assert "create SNS topic" in captured.out
    assert "Final bucket policy:" in captured.out
    assert (
        "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications" in captured.out
    )
    assert "Final SNS topic policy:" in captured.out
    assert "Final bucket notification configuration:" in captured.out

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


@pytest.mark.parametrize(
    ("extra_args", "expected_result"),
    [(["--dry-run"], 0), ([], 1)],
    ids=["dry-run", "declined"],
)
def test_add_force_does_not_remove_before_execution(
    monkeypatch, extra_args, expected_result
) -> None:
    calls: list[tuple[str, str]] = []
    buckets = SimpleNamespace(
        get=lambda name: FakeBucket(name, "Existing Title"),
        remove=lambda name: calls.append(("remove", name)),
        add=lambda **kwargs: calls.append(("add", kwargs["name"])),
    )
    stack = make_fake_catalog(
        "demo",
        payload={"account_id": "123456789012", "region": "us-east-1"},
        buckets=buckets,
    )
    session = SimpleNamespace(client=lambda service, region_name=None: object())
    plan = _fake_bucket_preparation_plan()

    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kwargs: stack,
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {"account_id": "123456789012", "region": "us-east-1"},
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "resolve_bucket_session",
        lambda *args, **kwargs: (session, object(), plan.region, None),
    )
    monkeypatch.setattr(
        bucket_tool, "_get_session_account_id", lambda _session: plan.owning_account
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "build_bucket_preparation_plan",
        lambda *args, **kwargs: plan,
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "apply_bucket_preparation",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dry-run or declined confirmation must not apply")
        ),
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    result = bucket_tool.main(["add", "bucket", "--force", "--no-test", *extra_args])

    assert result == expected_result
    assert calls == []


def test_add_already_registered_reapplies_plumbing(monkeypatch, capsys) -> None:
    """Already-registered bucket: reapply S3 policy / SNS / principals, but
    skip the catalog ``admin.buckets.add`` GraphQL call.

    The whole point of ``bucket add`` is to set up access. The catalog row
    existing doesn't mean the bucket policy / SNS / cross-account grants are
    in place, so we always (idempotently) apply those — only the GraphQL
    registration is skipped when already present.
    """
    s3_client, s3_stubber = _stub_s3_for_full_add()
    sns_client, sns_stubber, topic_arn = _stub_sns_for_existing_topic()
    sts_client, sts_stubber = _stub_sts_caller_identity()

    add_calls: list[dict[str, str]] = []
    _install_fake_quilt3(
        monkeypatch,
        get_result=FakeBucket("bucket", "Existing Title"),
        add_calls=add_calls,
    )
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda profile_name=None: FakeSession(s3_client, sns_client, sts_client),
    )
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {
            "account_id": "123456789012",
            "outputs": [
                {
                    "OutputKey": "RegistryRoleARN",
                    "OutputValue": "arn:aws:iam::123456789012:role/quilt-registry",
                }
            ],
        },
    )
    monkeypatch.setattr(
        bucket_tool,
        "_verify_bucket_registration_and_access",
        lambda *args, **kwargs: 0,
    )

    assert bucket_tool.main(["add", "bucket", "--yes"]) == 0
    captured = capsys.readouterr()
    assert "already registered" in captured.out
    assert "reapplying access plumbing" in captured.out
    assert add_calls == []

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_add_already_registered_skips_post_test_when_no_test_flag(monkeypatch) -> None:
    s3_client, s3_stubber = _stub_s3_for_full_add()
    sns_client, sns_stubber, topic_arn = _stub_sns_for_existing_topic()
    sts_client, sts_stubber = _stub_sts_caller_identity()

    _install_fake_quilt3(
        monkeypatch,
        get_result=FakeBucket("bucket", "Existing Title"),
        add_calls=[],
    )
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda profile_name=None: FakeSession(s3_client, sns_client, sts_client),
    )
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {
            "account_id": "123456789012",
            "outputs": [
                {
                    "OutputKey": "RegistryRoleARN",
                    "OutputValue": "arn:aws:iam::123456789012:role/quilt-registry",
                }
            ],
        },
    )
    monkeypatch.setattr(
        bucket_tool,
        "_verify_bucket_registration_and_access",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not run")),
    )

    assert bucket_tool.main(["add", "bucket", "--yes", "--no-test"]) == 0

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_add_no_preflight_registers_without_boto3(monkeypatch, capsys) -> None:
    add_calls: list[tuple[str, str | None]] = []
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("boto3 should not be used")
        ),
    )
    monkeypatch.setattr(
        bucket_tool,
        "_verify_bucket_registration_and_access",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("post-add test should not run")
        ),
    )

    def fake_add_without_preflight(stack, bucket, *, title=None):
        add_calls.append((bucket, title))
        return AddBucketResult(bucket, title or bucket, "", False)

    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "add_bucket_without_preflight",
        fake_add_without_preflight,
    )

    assert bucket_tool.main(["add", "bucket", "--yes", "--no-preflight"]) == 0
    captured = capsys.readouterr()
    assert "via GraphQL only" in captured.out
    assert "local AWS preflight/setup skipped" in captured.out
    assert add_calls == [("bucket", "bucket")]


def test_add_no_preflight_env_var(monkeypatch) -> None:
    add_calls: list[str] = []
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])
    _install_stack_context(monkeypatch)
    monkeypatch.setenv("QUILTX_NO_PREFLIGHT", "1")
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("boto3 should not be used")
        ),
    )

    def fake_add_without_preflight(stack, bucket, *, title=None):
        add_calls.append(bucket)
        return AddBucketResult(bucket, title or bucket, "", False)

    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "add_bucket_without_preflight",
        fake_add_without_preflight,
    )

    assert bucket_tool.main(["add", "bucket", "--yes"]) == 0
    assert add_calls == ["bucket"]


def test_add_no_preflight_no_prompt_does_not_require_yes(monkeypatch) -> None:
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "add_bucket_without_preflight",
        lambda stack, bucket, *, title=None: AddBucketResult(
            bucket, title or bucket, "", False
        ),
    )

    assert bucket_tool.main(["add", "bucket", "--no-preflight", "--no-prompt"]) == 0


def test_add_no_preflight_force_removes_then_adds(monkeypatch) -> None:
    calls: list[tuple[str, str]] = []
    _install_stack_context(monkeypatch)

    buckets = SimpleNamespace()
    buckets.get = lambda name: FakeBucket(name, "Existing")
    buckets.remove = lambda name: calls.append(("remove", name))
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: make_fake_catalog("demo", buckets=buckets),
    )

    def fake_add_without_preflight(stack, bucket, *, title=None):
        calls.append(("add", bucket))
        return AddBucketResult(bucket, title or bucket, "", False)

    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "add_bucket_without_preflight",
        fake_add_without_preflight,
    )

    assert (
        bucket_tool.main(["add", "bucket", "--yes", "--no-preflight", "--force"]) == 0
    )
    assert calls == [("remove", "bucket"), ("add", "bucket")]


@pytest.mark.parametrize(
    ("typename", "message", "expected"),
    [
        (
            "BucketDoesNotExist",
            "",
            "The stack cannot access this bucket",
        ),
        (
            "InsufficientPermissions",
            "missing s3:ListBucket",
            "missing s3:ListBucket",
        ),
        ("NotificationConfigurationError", "", "NotificationConfigurationError"),
        ("NotificationTopicNotFound", "", "NotificationTopicNotFound"),
        ("SnsInvalid", "", "SnsInvalid"),
        ("SubscriptionInvalid", "", "SubscriptionInvalid"),
        (
            "BucketFileExtensionsToIndexInvalid",
            "",
            "BucketFileExtensionsToIndexInvalid",
        ),
        (
            "BucketIndexContentBytesInvalid",
            "",
            "BucketIndexContentBytesInvalid",
        ),
    ],
)
def test_bucket_add_union_error_messages(typename, message, expected) -> None:
    result = SimpleNamespace(typename__=typename, message=message)

    assert expected in bucket_lib._bucket_add_error_message(result, typename)


def _stub_s3_for_full_add():
    """S3 stubs for planning, revalidation, and applying a registered bucket."""
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    topic_arn = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    bucket_policy = {"Version": "2012-10-17", "Statement": []}
    notifications = {
        "TopicConfigurations": [
            {
                "Id": "QuiltBucketNotifications",
                "TopicArn": topic_arn,
                "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
            }
        ]
    }
    final_policy = bucket_lib.merge_bucket_policy(
        bucket_policy,
        bucket_lib.build_quilt_policy_statement("bucket", "123456789012"),
    )
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "bucket"},
    )
    for _ in range(2):
        s3_stubber.add_response(
            "get_bucket_policy",
            {"Policy": json.dumps(bucket_policy)},
            {"Bucket": "bucket"},
        )
        s3_stubber.add_response(
            "get_bucket_notification_configuration",
            notifications,
            {"Bucket": "bucket"},
        )
    # Recheck immediately before the bucket-policy write.
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(bucket_policy)},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {"Bucket": "bucket", "Policy": json.dumps(final_policy)},
    )
    s3_stubber.activate()
    return s3_client, s3_stubber


def _stub_sns_for_existing_topic():
    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    topic_arn = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    final_policy = bucket_lib.build_sns_topic_policy(
        None,
        "bucket",
        topic_arn,
        "111122223333",
        ["arn:aws:iam::123456789012:root"],
    )
    for _ in range(3):
        sns_stubber.add_response(
            "get_topic_attributes",
            {"Attributes": {}},
            {"TopicArn": topic_arn},
        )
    sns_stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
            "AttributeName": "Policy",
            "AttributeValue": json.dumps(final_policy),
        },
    )
    sns_stubber.activate()
    return sns_client, sns_stubber, topic_arn


def _stub_sts_caller_identity():
    sts_client = _client("sts")
    sts_stubber = Stubber(sts_client)
    sts_stubber.add_response(
        "get_caller_identity",
        {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:user/test",
            "UserId": "test",
        },
        {},
    )
    sts_stubber.activate()
    return sts_client, sts_stubber


def test_add_no_config(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: (_ for _ in ()).throw(
            ValueError("No Quilt catalog configured")
        ),
    )

    assert bucket_tool.main(["add", "bucket", "--dry-run"]) == 1
    captured = capsys.readouterr()
    assert "No Quilt catalog configured" in captured.err


def test_add_no_stack_cache_auto_discovers(monkeypatch, capsys) -> None:
    """When no cached stack payload exists, _ensure_stack_payload auto-discovers."""
    call_count = {"n": 0}

    def _load_stack_payload(catalog_name):
        call_count["n"] += 1
        if call_count["n"] <= 1:
            return None  # first call: no cache
        return {
            "account_id": "123456789012",
            "stack_name": "quilt",
            "region": "us-east-1",
            "outputs": [],
        }

    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.stack_lib, "load_stack_payload", _load_stack_payload
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "fetch_catalog_config",
        lambda url: {"region": "us-east-1"},
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib, "fetch_region", lambda ctx, cc: "us-east-1"
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "find_matching_stack",
        lambda stack, region: {
            "StackName": "quilt",
            "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/quilt/abc",
        },
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "list_log_group_resources",
        lambda stack, name, region: [],
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "list_ecs_resources",
        lambda stack, name, region: [],
    )
    monkeypatch.setattr(
        bucket_tool.stack_lib, "write_stack_payload", lambda *a, **kw: None
    )

    # Should fail later (no S3 stub), but NOT with the missing-payload guidance.
    assert bucket_tool.main(["add", "bucket", "--dry-run"]) == 1
    captured = capsys.readouterr()
    assert "quiltx catalog stack" not in captured.err
    assert "Discovering stack" in captured.out


def test_add_rejects_unrelated_existing_sns(monkeypatch, capsys) -> None:
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps({"Version": "2012-10-17", "Statement": []})},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "existing",
                    "TopicArn": "arn:aws:sns:us-west-2:111122223333:existing",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        },
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    sns_stubber.activate()

    sts_client = _client("sts")
    sts_stubber = Stubber(sts_client)
    sts_stubber.add_response(
        "get_caller_identity",
        {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:user/test",
            "UserId": "test",
        },
        {},
    )
    sts_stubber.activate()

    add_calls: list[dict[str, str]] = []
    _install_fake_quilt3(monkeypatch, add_calls=add_calls)
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda profile_name=None: FakeSession(s3_client, sns_client, sts_client),
    )
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {
            "account_id": "123456789012",
            "outputs": [
                {
                    "OutputKey": "RegistryRoleARN",
                    "OutputValue": "arn:aws:iam::123456789012:role/quilt-registry",
                }
            ],
        },
    )

    assert bucket_tool.main(["add", "bucket", "--title", "Demo Bucket", "--yes"]) == 1
    assert "overlaps Quilt's unfiltered" in capsys.readouterr().err
    assert add_calls == []

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_add_creates_sns(monkeypatch) -> None:
    topic_arn = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    bucket_policy = {"Version": "2012-10-17", "Statement": []}
    final_bucket_policy = bucket_lib.merge_bucket_policy(
        bucket_policy,
        bucket_lib.build_quilt_policy_statement("bucket", "123456789012"),
    )
    final_notifications = bucket_lib.build_bucket_notification_configuration(
        {}, topic_arn
    )
    final_sns_policy = bucket_lib.build_sns_topic_policy(
        None,
        "bucket",
        topic_arn,
        "111122223333",
        ["arn:aws:iam::123456789012:root"],
    )

    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "bucket"},
    )
    for _ in range(2):
        s3_stubber.add_response(
            "get_bucket_policy",
            {"Policy": json.dumps(bucket_policy)},
            {"Bucket": "bucket"},
        )
        s3_stubber.add_response(
            "get_bucket_notification_configuration", {}, {"Bucket": "bucket"}
        )
    # Recheck immediately before each write.
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(bucket_policy)},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {"Bucket": "bucket", "Policy": json.dumps(final_bucket_policy)},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration", {}, {"Bucket": "bucket"}
    )
    s3_stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {"Bucket": "bucket", "NotificationConfiguration": final_notifications},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    for _ in range(2):
        sns_stubber.add_client_error(
            "get_topic_attributes",
            service_error_code="NotFound",
            expected_params={"TopicArn": topic_arn},
        )
    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": topic_arn},
        {"Name": "quilt-bucket-notifications"},
    )
    # Recheck the just-created topic still carries only the default owner policy.
    sns_stubber.add_response(
        "get_topic_attributes",
        {
            "Attributes": {
                "Policy": json.dumps(
                    bucket_lib._build_default_sns_owner_policy(
                        topic_arn, "111122223333"
                    )
                )
            }
        },
        {"TopicArn": topic_arn},
    )
    sns_stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
            "AttributeName": "Policy",
            "AttributeValue": json.dumps(final_sns_policy),
        },
    )
    sns_stubber.activate()

    sts_client = _client("sts")
    sts_stubber = Stubber(sts_client)
    sts_stubber.add_response(
        "get_caller_identity",
        {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:user/test",
            "UserId": "test",
        },
        {},
    )
    sts_stubber.activate()

    add_calls: list[dict[str, str]] = []
    _install_fake_quilt3(monkeypatch, add_calls=add_calls)
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda profile_name=None: FakeSession(s3_client, sns_client, sts_client),
    )
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {
            "account_id": "123456789012",
            "outputs": [
                {
                    "OutputKey": "RegistryRoleARN",
                    "OutputValue": "arn:aws:iam::123456789012:role/quilt-registry",
                }
            ],
        },
    )

    assert bucket_tool.main(["add", "bucket", "--yes"]) == 0
    assert add_calls == [
        {
            "name": "bucket",
            "title": "bucket",
            "sns_notification_arn": topic_arn,
        }
    ]

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_list(monkeypatch, capsys) -> None:
    _install_stack_context(monkeypatch)
    _install_fake_quilt3(
        monkeypatch,
        listed=[
            FakeBucket(
                "bucket-a",
                "Bucket A",
                "arn:aws:sns:us-east-1:123:topic",
                ["prefix/a", "prefix/b"],
            )
        ],
    )

    assert bucket_tool.main(["list"]) == 0
    captured = capsys.readouterr()
    assert "bucket-a" in captured.out
    assert "Bucket A" in captured.out


def test_test_checks_registration_and_read_access(monkeypatch, capsys) -> None:
    _install_stack_context(monkeypatch)
    _install_fake_quilt3(
        monkeypatch,
        listed=[FakeBucket("bucket-a", "Bucket A")],
    )

    assert bucket_tool.main(["test", "bucket-a"]) == 0
    captured = capsys.readouterr()
    assert "OK: bucket-a is registered in Quilt as Bucket A" in captured.out
    assert "OK: search index is populated" in captured.out


def test_test_fails_when_bucket_not_registered(monkeypatch, capsys) -> None:
    _install_stack_context(monkeypatch)
    _install_fake_quilt3(monkeypatch, listed=[FakeBucket("other", "Other")])

    assert bucket_tool.main(["test", "bucket-a"]) == 1
    captured = capsys.readouterr()
    assert "bucket-a is not registered in Quilt" in captured.err


def test_build_parser_uses_bucket_prog() -> None:
    parser = bucket_tool.build_parser()
    assert parser.prog == "quiltx bucket"
    help_text = parser.format_help()
    assert "actions:" in help_text
    assert "ACTION" in help_text
    assert "{add,list,test}" not in help_text
    with contextlib.suppress(SystemExit):
        parser.parse_args(["add", "--help"])


def test_confirm_bucket_add_renders_existing_topic_context(monkeypatch, capsys) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    plan = replace(_fake_bucket_preparation_plan(), topic_exists=True)

    assert bucket_tool._confirm_bucket_add(
        "demo",
        "https://demo.example.com",
        "quilt-demo-stack",
        "123456789012",
        ["arn:aws:iam::123456789012:role/quilt-registry"],
        "--principal",
        "us-east-1",
        "open",
        plan,
    )

    captured = capsys.readouterr()
    assert "Bucket add confirmation" in captured.out
    assert "arn:aws:iam::123456789012:role/quilt-registry" in captured.out
    assert "--principal" in captured.out
    assert "s3://bucket" in captured.out
    assert "reuse quiltx SNS topic" in captured.out
    assert "quilt-bucket-notifications" in captured.out
    assert "AWS profile open" in captured.out


def test_confirm_bucket_add_renders_planned_topic_creation(monkeypatch, capsys) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    plan = _fake_bucket_preparation_plan()

    assert not bucket_tool._confirm_bucket_add(
        "demo",
        "https://demo.example.com",
        None,
        "123456789012",
        list(plan.principals),
        "account root (default)",
        "us-east-1",
        None,
        plan,
    )

    output = capsys.readouterr().out
    assert "create SNS topic" in output
    assert plan.sns_topic_arn in output
    assert "reuse existing SNS topic" not in output


def test_sns_topic_source_labels_known_topic_names() -> None:
    assert (
        bucket_tool._sns_topic_source(
            "bucket",
            "arn:aws:sns:us-east-1:123456789012:quilt-bucket-notifications",
        )
        == "reuse quiltx SNS topic"
    )
    assert (
        bucket_tool._sns_topic_source(
            "bucket",
            "arn:aws:sns:us-east-1:123456789012:bucket-QuiltNotifications-abc",
        )
        == "reuse Quilt SNS topic"
    )
    assert (
        bucket_tool._sns_topic_source(
            "bucket",
            "arn:aws:sns:us-east-1:123456789012:custom-topic",
        )
        == "reuse existing SNS topic"
    )


# -- Tests for high-level add_bucket() API --


def _stub_stack_and_config(monkeypatch, *, payload=None):
    """Build a stack fixture for add_bucket tests."""
    return bucket_tool.stack_lib.Catalog(
        catalog_name="demo",
        catalog_url="https://demo.example.com",
        source="global-config",
        auth_required=False,
    )


def _default_stack_payload() -> dict[str, object]:
    return {
        "account_id": "123456789012",
        "outputs": [
            {
                "OutputKey": "RegistryRoleARN",
                "OutputValue": "arn:aws:iam::123456789012:role/quilt-registry",
            }
        ],
    }


def _stack_for_add_bucket(
    monkeypatch, *, payload: dict[str, object] | None = None
) -> Any:
    stack = _stub_stack_and_config(monkeypatch)
    monkeypatch.setattr(
        type(stack),
        "payload",
        property(
            lambda _stack: _default_stack_payload() if payload is None else payload
        ),
    )
    return stack


def _install_add_bucket_preparation_fakes(
    monkeypatch, plan: bucket_lib.BucketPreparationPlan
) -> list[bucket_lib.BucketPreparationPlan]:
    s3_client = object()
    sns_client = object()
    sts_client = SimpleNamespace(
        get_caller_identity=lambda: {"Account": plan.owning_account}
    )
    session = FakeSession(s3_client, sns_client, sts_client)
    applied: list[bucket_lib.BucketPreparationPlan] = []

    monkeypatch.setattr(boto3, "Session", lambda profile_name=None: session)
    monkeypatch.setattr(
        bucket_lib, "get_bucket_region", lambda bucket, *, s3_client: plan.region
    )
    monkeypatch.setattr(
        bucket_lib,
        "build_bucket_preparation_plan",
        lambda *args, **kwargs: plan,
    )
    monkeypatch.setattr(
        bucket_lib,
        "apply_bucket_preparation",
        lambda candidate, **kwargs: applied.append(candidate),
    )
    return applied


def test_add_bucket_already_registered_still_prepares(monkeypatch) -> None:
    plan = _fake_bucket_preparation_plan()
    applied = _install_add_bucket_preparation_fakes(monkeypatch, plan)
    stack = _stack_for_add_bucket(monkeypatch)
    add_calls: list[dict[str, str]] = []
    _install_fake_quilt3(
        monkeypatch,
        get_result=FakeBucket("bucket", "My Bucket"),
        add_calls=add_calls,
    )

    result = add_bucket(stack, "bucket")

    assert result == AddBucketResult(
        bucket="bucket",
        title="My Bucket",
        sns_topic_arn=plan.sns_topic_arn,
        already_registered=True,
    )
    assert applied == [plan]
    assert add_calls == []


def test_add_bucket_creates_new(monkeypatch) -> None:
    topic_arn = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    bucket_policy = {"Version": "2012-10-17", "Statement": []}
    final_bucket_policy = bucket_lib.merge_bucket_policy(
        bucket_policy,
        bucket_lib.build_quilt_policy_statement("bucket", "123456789012"),
    )
    final_notifications = bucket_lib.build_bucket_notification_configuration(
        {}, topic_arn
    )
    final_sns_policy = bucket_lib.build_sns_topic_policy(
        None,
        "bucket",
        topic_arn,
        "111122223333",
        ["arn:aws:iam::123456789012:root"],
    )

    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "bucket"},
    )
    for _ in range(2):
        s3_stubber.add_response(
            "get_bucket_policy",
            {"Policy": json.dumps(bucket_policy)},
            {"Bucket": "bucket"},
        )
        s3_stubber.add_response(
            "get_bucket_notification_configuration", {}, {"Bucket": "bucket"}
        )
    # Recheck immediately before each write.
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(bucket_policy)},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {"Bucket": "bucket", "Policy": json.dumps(final_bucket_policy)},
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration", {}, {"Bucket": "bucket"}
    )
    s3_stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {"Bucket": "bucket", "NotificationConfiguration": final_notifications},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    for _ in range(2):
        sns_stubber.add_client_error(
            "get_topic_attributes",
            service_error_code="NotFound",
            expected_params={"TopicArn": topic_arn},
        )
    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": topic_arn},
        {"Name": "quilt-bucket-notifications"},
    )
    # Recheck the just-created topic still carries only the default owner policy.
    sns_stubber.add_response(
        "get_topic_attributes",
        {
            "Attributes": {
                "Policy": json.dumps(
                    bucket_lib._build_default_sns_owner_policy(
                        topic_arn, "111122223333"
                    )
                )
            }
        },
        {"TopicArn": topic_arn},
    )
    sns_stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
            "AttributeName": "Policy",
            "AttributeValue": json.dumps(final_sns_policy),
        },
    )
    sns_stubber.activate()

    sts_client = _client("sts")
    sts_stubber = Stubber(sts_client)
    sts_stubber.add_response(
        "get_caller_identity",
        {
            "Account": "111122223333",
            "Arn": "arn:aws:iam::111122223333:user/test",
            "UserId": "test",
        },
        {},
    )
    sts_stubber.activate()

    add_calls: list[dict[str, str]] = []
    _install_fake_quilt3(monkeypatch, add_calls=add_calls)
    stack = _stack_for_add_bucket(monkeypatch)

    session = FakeSession(s3_client, sns_client, sts_client)
    import boto3 as _boto3

    monkeypatch.setattr(_boto3, "Session", lambda profile_name=None: session)

    result = add_bucket(stack, "bucket", title="Demo Bucket")
    assert result == AddBucketResult(
        bucket="bucket",
        title="Demo Bucket",
        sns_topic_arn=topic_arn,
        already_registered=False,
    )
    assert add_calls == [
        {
            "name": "bucket",
            "title": "Demo Bucket",
            "sns_notification_arn": topic_arn,
        }
    ]

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_add_bucket_no_stack_payload(monkeypatch) -> None:
    stack = _stack_for_add_bucket(monkeypatch, payload={})
    _install_fake_quilt3(monkeypatch)

    try:
        add_bucket(stack, "bucket")
    except ValueError as exc:
        assert "stack" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError")


def test_add_bucket_defaults_title_to_bucket_name(monkeypatch) -> None:
    plan = replace(_fake_bucket_preparation_plan(), bucket="my-data")
    applied = _install_add_bucket_preparation_fakes(monkeypatch, plan)
    stack = _stack_for_add_bucket(monkeypatch)
    add_calls: list[dict[str, str]] = []
    _install_fake_quilt3(monkeypatch, add_calls=add_calls)

    result = add_bucket(stack, "my-data")

    assert result.title == "my-data"
    assert result.already_registered is False
    assert applied == [plan]
    assert add_calls == [
        {
            "name": "my-data",
            "title": "my-data",
            "sns_notification_arn": plan.sns_topic_arn,
        }
    ]


# -- Tests for --principal --


def test_build_quilt_policy_statement_with_single_principal() -> None:
    role_arn = "arn:aws:iam::123456789012:role/quilt-lambda"
    statement = bucket_lib.build_quilt_policy_statement(
        "demo-bucket", "123456789012", principals=[role_arn]
    )
    assert statement["Principal"] == {"AWS": role_arn}


def test_build_quilt_policy_statement_with_multiple_principals() -> None:
    arns = [
        "arn:aws:iam::123456789012:role/quilt-lambda",
        "arn:aws:iam::123456789012:role/quilt-indexer",
    ]
    statement = bucket_lib.build_quilt_policy_statement(
        "demo-bucket", "123456789012", principals=arns
    )
    assert statement["Principal"] == {"AWS": arns}


def test_build_quilt_policy_statement_without_principals_uses_root() -> None:
    statement = bucket_lib.build_quilt_policy_statement("demo-bucket", "123456789012")
    assert statement["Principal"] == {"AWS": "arn:aws:iam::123456789012:root"}


def test_resolve_principals_arg_bare_flag_requests_guidance() -> None:
    principals, show_guidance = bucket_tool._resolve_principals_arg([""])
    assert principals == []
    assert show_guidance is True


def test_resolve_principals_arg_splits_comma_separated() -> None:
    principals, show_guidance = bucket_tool._resolve_principals_arg(
        ["arn:aws:iam::1:role/A,arn:aws:iam::1:role/B", "arn:aws:iam::1:role/C"]
    )
    assert principals == [
        "arn:aws:iam::1:role/A",
        "arn:aws:iam::1:role/B",
        "arn:aws:iam::1:role/C",
    ]
    assert show_guidance is False


def test_cmd_add_principal_bare_flag_prints_guidance(monkeypatch, capsys) -> None:
    cat = make_fake_catalog("nightly.quilttest.com")
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: cat,
    )
    assert bucket_tool.main(["add", "bucket", "--principal"]) == 0
    captured = capsys.readouterr()
    assert "--principal" in captured.out
    assert "control account root" in captured.out
    assert "docs.quilt.bio" in captured.out


def test_cmd_add_principal_rejects_non_arn(monkeypatch, capsys) -> None:
    cat = make_fake_catalog("nightly.quilttest.com")
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: cat,
    )
    assert bucket_tool.main(["add", "bucket", "--principal", "not-an-arn"]) == 1
    captured = capsys.readouterr()
    assert "must be an IAM role ARN" in captured.err


def test_cmd_add_no_prompt_without_yes_exits_early(monkeypatch, capsys) -> None:
    """--no-prompt without --yes prints an error and returns 1 before any AWS calls."""
    cat = make_fake_catalog("nightly.quilttest.com")
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: cat,
    )
    result = bucket_tool.main(["add", "bucket", "--no-prompt"])
    assert result == 1
    err = capsys.readouterr().err
    assert "--no-prompt" in err
    assert "--yes" in err


def test_cmd_add_no_prompt_with_dry_run_requires_yes(monkeypatch, capsys) -> None:
    """--no-prompt guard checks --yes regardless of --dry-run."""
    cat = make_fake_catalog("nightly.quilttest.com")
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "resolve_catalog_context",
        lambda _catalog=None, **kw: cat,
    )
    result = bucket_tool.main(["add", "bucket", "--no-prompt", "--dry-run"])
    assert result == 1
    assert "--yes" in capsys.readouterr().err


def test_cmd_profile_lists_profiles(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda *a, **kw: SimpleNamespace(available_profiles=["sales", "open", "prod"]),
    )
    assert bucket_tool.main(["profile"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["sales", "open", "prod"]


def test_cmd_profile_no_profiles(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        bucket_tool.boto3,
        "Session",
        lambda *a, **kw: SimpleNamespace(available_profiles=[]),
    )
    assert bucket_tool.main(["profile"]) == 1
    assert "No AWS profiles" in capsys.readouterr().err


def test_cmd_profile_finds_profile_for_bucket(monkeypatch, capsys) -> None:
    from botocore.exceptions import ClientError

    calls: list[str] = []

    class FakeS3:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def get_bucket_location(self, Bucket: str) -> dict:
            calls.append(self.profile)
            if self.profile == "prod":
                return {"LocationConstraint": None}
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "GetBucketLocation",
            )

    class FakeSession:
        def __init__(self, profile_name: str | None = None) -> None:
            self.profile_name = profile_name

        available_profiles = ["sales", "open", "prod"]

        def client(self, service: str):
            return FakeS3(self.profile_name or "")

    monkeypatch.setattr(bucket_tool.boto3, "Session", FakeSession)
    assert bucket_tool.main(["profile", "quilt-example"]) == 0
    assert capsys.readouterr().out.strip() == "prod"
    assert calls == ["sales", "open", "prod"]


def test_resolve_bucket_session_switches_on_access_denied(monkeypatch, capsys) -> None:
    from botocore.exceptions import ClientError

    class FakeS3:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def get_bucket_location(self, Bucket: str) -> dict:
            if self.profile == "prod":
                return {"LocationConstraint": None}
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "GetBucketLocation",
            )

    class FakeSession:
        available_profiles = ["sales", "prod"]

        def __init__(self, profile_name: str | None = None) -> None:
            self.profile_name = profile_name or ""

        def client(self, service: str, region_name: str | None = None):
            return FakeS3(self.profile_name)

    monkeypatch.setattr(bucket_tool.boto3, "Session", FakeSession)

    session, s3_client, region, profile = bucket_lib.resolve_bucket_session(
        "quilt-example", "sales", assume_yes=True
    )
    assert profile == "prod"
    assert region == "us-east-1"
    assert isinstance(session, FakeSession)
    assert session.profile_name == "prod"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Retrying with profile prod." in captured.err


def test_resolve_bucket_session_aborts_when_user_declines(monkeypatch, capsys) -> None:
    from botocore.exceptions import ClientError

    class FakeS3:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def get_bucket_location(self, Bucket: str) -> dict:
            if self.profile == "prod":
                return {"LocationConstraint": None}
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "GetBucketLocation",
            )

    class FakeSession:
        available_profiles = ["sales", "prod"]

        def __init__(self, profile_name: str | None = None) -> None:
            self.profile_name = profile_name or ""

        def client(self, service: str, region_name: str | None = None):
            return FakeS3(self.profile_name)

    monkeypatch.setattr(bucket_tool.boto3, "Session", FakeSession)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    session, _s3, _region, profile = bucket_lib.resolve_bucket_session(
        "quilt-example", "sales", assume_yes=False
    )
    assert session is None
    assert profile == "sales"


def test_cmd_profile_no_matching_profile(monkeypatch, capsys) -> None:
    from botocore.exceptions import ClientError

    class FakeS3:
        def get_bucket_location(self, Bucket: str) -> dict:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "GetBucketLocation",
            )

    class FakeSession:
        def __init__(self, profile_name: str | None = None) -> None:
            pass

        available_profiles = ["sales", "open"]

        def client(self, service: str):
            return FakeS3()

    monkeypatch.setattr(bucket_tool.boto3, "Session", FakeSession)
    assert bucket_tool.main(["profile", "nope"]) == 1
    assert "No configured profile" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# `quiltx bucket reindex` tests
# ---------------------------------------------------------------------------


def test_parse_s3_uri_full() -> None:
    assert bucket_tool.parse_s3_uri("s3://my-bucket/some/prefix/") == (
        "my-bucket",
        "some/prefix/",
    )


def test_parse_s3_uri_bucket_only() -> None:
    # No trailing slash => empty prefix.
    assert bucket_tool.parse_s3_uri("s3://my-bucket") == ("my-bucket", "")


def test_parse_s3_uri_bucket_root_with_slash() -> None:
    assert bucket_tool.parse_s3_uri("s3://my-bucket/") == ("my-bucket", "")


def test_parse_s3_uri_bucket_with_key() -> None:
    assert bucket_tool.parse_s3_uri("s3://my-bucket/x") == ("my-bucket", "x")


def test_parse_s3_uri_rejects_non_s3() -> None:
    import pytest

    with pytest.raises(ValueError):
        bucket_tool.parse_s3_uri("https://example.com/foo")


def test_parse_s3_uri_rejects_empty_bucket() -> None:
    import pytest

    with pytest.raises(ValueError):
        bucket_tool.parse_s3_uri("s3://")
    with pytest.raises(ValueError):
        bucket_tool.parse_s3_uri("s3:///foo")


def test_reindex_arg_parser_defaults() -> None:
    parser = bucket_tool.build_parser()
    args = parser.parse_args(["reindex", "s3://b/p/"])
    assert args.action == "reindex"
    assert args.s3_uri == "s3://b/p/"
    assert args.dry_run is False
    assert args.sample == 10


def test_reindex_arg_parser_flags() -> None:
    parser = bucket_tool.build_parser()
    args = parser.parse_args(["reindex", "s3://b/p/", "--dry-run", "--sample", "3"])
    assert args.dry_run is True
    assert args.sample == 3


def test_bucket_subcommands_accept_catalog_and_api_key() -> None:
    """Story 2 headless ladder: every auth-required bucket subcommand
    must accept --catalog and --api-key."""
    parser = bucket_tool.build_parser()
    cases: list[tuple[str, list[str]]] = [
        ("add", ["my-bucket"]),
        ("remove", ["my-bucket"]),
        ("list", []),
        ("test", ["my-bucket"]),
        ("reindex", ["s3://my-bucket/"]),
    ]
    for action, extra in cases:
        args = parser.parse_args(
            [action, "--catalog", "customer-acme", "--api-key", "qk_test", *extra]
        )
        assert args.catalog == "customer-acme", action
        assert args.api_key == "qk_test", action


def test_bucket_profile_does_not_accept_api_key() -> None:
    """`bucket profile` is AWS-side only — Quilt auth flags do not apply."""
    import pytest

    parser = bucket_tool.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["profile", "--api-key", "qk_test"])
    with pytest.raises(SystemExit):
        parser.parse_args(["profile", "--catalog", "x"])


def test_reindex_dry_run_lists_keys(monkeypatch, capsys) -> None:
    """Dry-run lists keys via list_object_versions and does NOT POST."""

    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "b"},
    )
    s3_stubber.add_response(
        "list_object_versions",
        {
            "Versions": [
                {"Key": "p/one", "VersionId": "v1"},
                {"Key": "p/two", "VersionId": "v2"},
            ],
            "DeleteMarkers": [
                {"Key": "p/three", "VersionId": "v3"},
            ],
            "IsTruncated": False,
        },
        {"Bucket": "b", "Prefix": "p/"},
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sts_client = _client("sts", region_name="us-west-2")
    session = FakeSession(s3_client, sns_client, sts_client)
    monkeypatch.setattr(bucket_tool.boto3, "Session", lambda profile_name=None: session)

    # Make sure we never reach the registry POST.
    def _boom(*_args, **_kwargs):
        raise AssertionError("dry-run must not import quilt3.session")

    fake_quilt3_session = ModuleType("quilt3.session")
    fake_quilt3_session.get_registry_url = _boom  # type: ignore[attr-defined]
    fake_quilt3_session.get_session = _boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_quilt3_session)

    rc = bucket_tool.main(["reindex", "s3://b/p/", "--dry-run"])
    assert rc == 0

    out = capsys.readouterr().out
    assert "Dry-run" in out
    assert "Object versions found: 3" in out
    assert "p/one" in out
    assert "p/three" in out
    assert "delete-marker" in out


def test_reindex_post_sends_prefix(monkeypatch, capsys) -> None:
    """Non-dry-run posts {"prefix": ...} to /api/admin/reindex/<bucket>."""

    _install_stack_context(monkeypatch)
    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200
        ok = True
        text = "{}"

        def json(self):
            return {}

    class FakeHttpSession:
        def post(self, url, json=None, **_kwargs):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

    fake_session_module = ModuleType("quilt3.session")
    fake_session_module.get_registry_url = lambda: "https://registry.example.com"  # type: ignore[attr-defined]
    fake_session_module.get_session = lambda: FakeHttpSession()  # type: ignore[attr-defined]

    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session_module)

    rc = bucket_tool.main(["reindex", "s3://b/some/prefix/"])
    assert rc == 0

    assert captured["url"] == "https://registry.example.com/api/admin/reindex/b"
    assert captured["json"] == {"prefix": "some/prefix/"}

    out = capsys.readouterr().out
    assert "Enqueued reindex for s3://b/some/prefix/" in out


def test_reindex_post_normalizes_registry_url_trailing_slash(monkeypatch) -> None:
    _install_stack_context(monkeypatch)
    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200
        ok = True
        text = "{}"

    class FakeHttpSession:
        def post(self, url, json=None, **_kwargs):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

    fake_session_module = ModuleType("quilt3.session")
    fake_session_module.get_registry_url = lambda: "https://registry.example.com/"  # type: ignore[attr-defined]
    fake_session_module.get_session = lambda: FakeHttpSession()  # type: ignore[attr-defined]

    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session_module)

    rc = bucket_tool.main(["reindex", "s3://b/p/"])
    assert rc == 0
    assert captured["url"] == "https://registry.example.com/api/admin/reindex/b"
    assert captured["json"] == {"prefix": "p/"}


def test_reindex_post_no_prefix_omits_field(monkeypatch) -> None:
    """``s3://bucket/`` should POST an empty body (whole-bucket reindex)."""
    _install_stack_context(monkeypatch)
    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200
        ok = True
        text = "{}"

    class FakeHttpSession:
        def post(self, url, json=None, **_kwargs):
            captured["json"] = json
            return FakeResponse()

    fake_session_module = ModuleType("quilt3.session")
    fake_session_module.get_registry_url = lambda: "https://registry.example.com"  # type: ignore[attr-defined]
    fake_session_module.get_session = lambda: FakeHttpSession()  # type: ignore[attr-defined]
    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session_module)

    rc = bucket_tool.main(["reindex", "s3://b/"])
    assert rc == 0
    assert captured["json"] == {}


def test_reindex_post_409_returns_error(monkeypatch, capsys) -> None:
    _install_stack_context(monkeypatch)

    class FakeResponse:
        status_code = 409
        ok = False
        text = "Indexing already in progress."

    class FakeHttpSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    fake_session_module = ModuleType("quilt3.session")
    fake_session_module.get_registry_url = lambda: "https://registry.example.com"  # type: ignore[attr-defined]
    fake_session_module.get_session = lambda: FakeHttpSession()  # type: ignore[attr-defined]
    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session_module)

    rc = bucket_tool.main(["reindex", "s3://b/p/"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "already in progress" in err


def test_reindex_post_404_returns_error(monkeypatch, capsys) -> None:
    _install_stack_context(monkeypatch)

    class FakeResponse:
        status_code = 404
        ok = False
        text = "Bucket not found"

    class FakeHttpSession:
        def post(self, *_args, **_kwargs):
            return FakeResponse()

    fake_session_module = ModuleType("quilt3.session")
    fake_session_module.get_registry_url = lambda: "https://registry.example.com"  # type: ignore[attr-defined]
    fake_session_module.get_session = lambda: FakeHttpSession()  # type: ignore[attr-defined]
    fake_quilt3 = ModuleType("quilt3")
    fake_quilt3.session = fake_session_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "quilt3", fake_quilt3)
    monkeypatch.setitem(sys.modules, "quilt3.session", fake_session_module)

    rc = bucket_tool.main(["reindex", "s3://b/p/"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not registered in this catalog" in err


def test_reindex_rejects_non_s3_uri(capsys) -> None:
    rc = bucket_tool.main(["reindex", "https://nope.example.com/x"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "s3://" in err


def test_add_no_preflight_bucket_add_error_exits_nonzero(monkeypatch, capsys) -> None:
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])
    _install_stack_context(monkeypatch)

    def boom(stack, bucket, *, title=None):
        raise bucket_lib.BucketAddError("BucketDoesNotExist: cannot reach bucket")

    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "add_bucket_without_preflight",
        boom,
    )

    rc = bucket_tool.main(["add", "bucket", "--no-preflight"])

    assert rc == 1
    captured = capsys.readouterr()
    assert "BucketDoesNotExist" in captured.err
    assert captured.err.startswith("Error: ")
    assert "BucketDoesNotExist" not in captured.out


def test_add_no_preflight_does_not_prompt_without_yes(monkeypatch) -> None:
    """Spec 7-no-preflight §144: --no-preflight should not need or trigger prompts."""
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])
    _install_stack_context(monkeypatch)
    monkeypatch.setattr(
        "builtins.input",
        lambda _prompt="": (_ for _ in ()).throw(
            AssertionError("--no-preflight must not prompt")
        ),
    )
    monkeypatch.setattr(
        bucket_tool.bucket_lib,
        "add_bucket_without_preflight",
        lambda stack, bucket, *, title=None: AddBucketResult(
            bucket, title or bucket, "", False
        ),
    )

    assert bucket_tool.main(["add", "bucket", "--no-preflight"]) == 0
