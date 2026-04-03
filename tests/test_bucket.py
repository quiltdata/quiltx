"""Tests for bucket helpers and the bucket tool."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from types import ModuleType, SimpleNamespace

import boto3
from botocore.stub import Stubber

from quiltx import bucket as bucket_lib
from quiltx.tools import bucket as bucket_tool


def _client(service_name: str, region_name: str = "us-east-1"):
    return boto3.client(
        service_name,
        region_name=region_name,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
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
    assert len(statement["Action"]) == 14


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
                "Action": "SNS:Publish",
                "Resource": topic_arn,
                "Condition": {
                    "ArnEquals": {"aws:SourceArn": "arn:aws:s3:::bucket"},
                    "StringEquals": {"aws:SourceAccount": "123456789012"},
                },
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
        sns_client=client,
    )

    stubber.deactivate()


def test_configure_notifications_merges() -> None:
    client = _client("s3")
    stubber = Stubber(client)
    stubber.add_response(
        "get_bucket_notification_configuration",
        {
            "LambdaFunctionConfigurations": [
                {
                    "Id": "lambda",
                    "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:f",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ],
            "QueueConfigurations": [
                {
                    "Id": "queue",
                    "QueueArn": "arn:aws:sqs:us-east-1:123456789012:q",
                    "Events": ["s3:ObjectRemoved:*"],
                }
            ],
        },
        {"Bucket": "bucket"},
    )
    stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": "bucket",
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "QuiltBucketNotifications",
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:topic",
                        "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                    }
                ],
                "QueueConfigurations": [
                    {
                        "Id": "queue",
                        "QueueArn": "arn:aws:sqs:us-east-1:123456789012:q",
                        "Events": ["s3:ObjectRemoved:*"],
                    }
                ],
                "LambdaFunctionConfigurations": [
                    {
                        "Id": "lambda",
                        "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:f",
                        "Events": ["s3:ObjectCreated:*"],
                    }
                ],
            },
        },
    )
    stubber.activate()

    bucket_lib.configure_bucket_notifications(
        "bucket",
        "arn:aws:sns:us-east-1:123456789012:topic",
        s3_client=client,
    )

    stubber.deactivate()


@dataclass
class FakeBucket:
    name: str
    title: str
    sns_notification_arn: str | None = None
    prefixes: list[str] | None = None


class FakeSession:
    def __init__(self, s3_client, sns_client, sts_client) -> None:
        self._s3_client = s3_client
        self._sns_client = sns_client
        self._sts_client = sts_client
        self.profile_name = None

    def client(self, service_name: str, region_name: str | None = None):
        if service_name == "s3":
            return self._s3_client
        if service_name == "sns":
            assert region_name == "us-west-2"
            return self._sns_client
        if service_name == "sts":
            return self._sts_client
        raise AssertionError(f"unexpected service: {service_name}")


def _install_fake_quilt3(monkeypatch, *, get_result=None, listed=None, add_calls=None):
    admin_buckets = SimpleNamespace()
    admin_buckets.get = lambda name: get_result
    admin_buckets.list = lambda: listed or []

    def add(**kwargs):
        if add_calls is not None:
            add_calls.append(kwargs)
        return FakeBucket(
            kwargs["name"], kwargs["title"], kwargs.get("sns_notification_arn"), []
        )

    admin_buckets.add = add

    admin_module = ModuleType("quilt3.admin")
    admin_module.buckets = admin_buckets
    quilt3_module = ModuleType("quilt3")
    quilt3_module.admin = admin_module
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
    monkeypatch.setattr(bucket_tool, "get_catalog_config", lambda: {"catalog": "demo"})
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {"account_id": "123456789012"},
    )
    _install_fake_quilt3(monkeypatch, get_result=None, add_calls=[])

    assert bucket_tool.main(["add", "bucket", "--dry-run"]) == 0
    captured = capsys.readouterr()
    assert "Planned bucket policy:" in captured.out
    assert "Planned SNS topic: create" in captured.out

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_add_skip_already_registered(monkeypatch, capsys) -> None:
    s3_client = _client("s3", region_name="us-west-2")
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_location",
        {"LocationConstraint": "us-west-2"},
        {"Bucket": "bucket"},
    )
    s3_stubber.activate()

    session = FakeSession(s3_client, _client("sns", "us-west-2"), _client("sts"))
    monkeypatch.setattr(bucket_tool.boto3, "Session", lambda profile_name=None: session)
    monkeypatch.setattr(bucket_tool, "get_catalog_config", lambda: {"catalog": "demo"})
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {"account_id": "123456789012"},
    )
    _install_fake_quilt3(monkeypatch, get_result=FakeBucket("bucket", "bucket"))

    assert bucket_tool.main(["add", "bucket", "--yes"]) == 0
    captured = capsys.readouterr()
    assert "already registered" in captured.out

    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_add_no_config(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        bucket_tool,
        "get_catalog_config",
        lambda: (_ for _ in ()).throw(ValueError("No Quilt catalog configured")),
    )

    assert bucket_tool.main(["add", "bucket", "--dry-run"]) == 1
    captured = capsys.readouterr()
    assert "No Quilt catalog configured" in captured.err


def test_add_no_stack_cache(monkeypatch, capsys) -> None:
    monkeypatch.setattr(bucket_tool, "get_catalog_config", lambda: {"catalog": "demo"})
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: None,
    )

    assert bucket_tool.main(["add", "bucket", "--dry-run"]) == 1
    captured = capsys.readouterr()
    assert "Run 'quiltx stack' first" in captured.err


def test_add_reuses_existing_sns(monkeypatch) -> None:
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
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {
            "Bucket": "bucket",
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        bucket_lib.build_quilt_policy_statement(
                            "bucket", "123456789012"
                        )
                    ],
                }
            ),
        },
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
    s3_stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": "bucket",
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "QuiltBucketNotifications",
                        "TopicArn": "arn:aws:sns:us-west-2:111122223333:existing",
                        "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                    }
                ]
            },
        },
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
    monkeypatch.setattr(bucket_tool, "get_catalog_config", lambda: {"catalog": "demo"})
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {"account_id": "123456789012"},
    )

    assert bucket_tool.main(["add", "bucket", "--title", "Demo Bucket", "--yes"]) == 0
    assert add_calls == [
        {
            "name": "bucket",
            "title": "Demo Bucket",
            "sns_notification_arn": "arn:aws:sns:us-west-2:111122223333:existing",
        }
    ]

    s3_stubber.assert_no_pending_responses()
    sns_stubber.assert_no_pending_responses()
    sts_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
    sns_stubber.deactivate()
    sts_stubber.deactivate()


def test_add_creates_sns(monkeypatch) -> None:
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
        {},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {
            "Bucket": "bucket",
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        bucket_lib.build_quilt_policy_statement(
                            "bucket", "123456789012"
                        )
                    ],
                }
            ),
        },
    )
    s3_stubber.add_response(
        "get_bucket_notification_configuration",
        {},
        {"Bucket": "bucket"},
    )
    s3_stubber.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": "bucket",
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "QuiltBucketNotifications",
                        "TopicArn": "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications",
                        "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"],
                    }
                ]
            },
        },
    )
    s3_stubber.activate()

    sns_client = _client("sns", region_name="us-west-2")
    sns_stubber = Stubber(sns_client)
    topic_arn = "arn:aws:sns:us-west-2:111122223333:quilt-bucket-notifications"
    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": topic_arn},
        {"Name": "quilt-bucket-notifications"},
    )
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
            "AttributeValue": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "QuiltBucketNotifications",
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "SNS:Publish",
                            "Resource": topic_arn,
                            "Condition": {
                                "ArnEquals": {"aws:SourceArn": "arn:aws:s3:::bucket"},
                                "StringEquals": {"aws:SourceAccount": "111122223333"},
                            },
                        }
                    ],
                }
            ),
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
    monkeypatch.setattr(bucket_tool, "get_catalog_config", lambda: {"catalog": "demo"})
    monkeypatch.setattr(
        bucket_tool.stack_lib,
        "load_stack_payload",
        lambda catalog_name: {"account_id": "123456789012"},
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
