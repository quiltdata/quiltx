"""Bucket policy and notification helpers for quiltx."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from botocore.exceptions import ClientError

from quiltx import stack as stack_lib
from quiltx.utils import get_bucket_region


def _reported_bucket_region(payload: Any) -> str | None:
    """Extract the bucket region S3 reports in a response or error payload.

    HeadBucket answers ``x-amz-bucket-region`` (surfaced as ``BucketRegion``)
    even when the call itself fails, which is how an out-of-region bucket can
    be told apart from one the caller cannot read at all.
    """
    if not isinstance(payload, Mapping):
        return None
    region = payload.get("BucketRegion")
    if region:
        return str(region)
    error = payload.get("Error")
    if isinstance(error, Mapping):
        region = error.get("BucketRegion") or error.get("Region")
        if region:
            return str(region)
    metadata = payload.get("ResponseMetadata")
    headers = metadata.get("HTTPHeaders") if isinstance(metadata, Mapping) else None
    if isinstance(headers, Mapping):
        region = headers.get("x-amz-bucket-region")
        if region:
            return str(region)
    return None


def head_bucket_region(s3_client: Any, bucket: str) -> str | None:
    """Return the region HeadBucket reports for *bucket*, or None if unknown.

    Best-effort probe: any failure to learn the region (including clients that
    do not implement HeadBucket) yields None so callers keep their original
    error.
    """
    try:
        response = s3_client.head_bucket(Bucket=bucket)
    except Exception as exc:  # region hint only; never mask the caller's error
        return _reported_bucket_region(getattr(exc, "response", None))
    return _reported_bucket_region(response)


def open_bucket_client(bucket: str, session: Any) -> tuple[Any, str]:
    """Return an S3 client bound to *bucket*'s region plus that region.

    Probes with the session's default region first, then retries against the
    region HeadBucket reports. Without the retry, a bucket outside the
    profile's default region answers ``AccessDenied`` on GetBucketLocation and
    looks unreachable even with a full cross-account grant (issue #91).

    Raises the underlying ``ClientError``/``BotoCoreError`` when the session
    genuinely cannot read the bucket.
    """
    from botocore.exceptions import BotoCoreError, ClientError

    s3_client = session.client("s3")
    try:
        return s3_client, get_bucket_region(bucket, s3_client=s3_client)
    except (ClientError, BotoCoreError):
        region = head_bucket_region(s3_client, bucket)
        probed_region = getattr(getattr(s3_client, "meta", None), "region_name", None)
        if region is None or region == probed_region:
            raise

    regional_client = session.client("s3", region_name=region)
    try:
        return regional_client, get_bucket_region(bucket, s3_client=regional_client)
    except (ClientError, BotoCoreError):
        # HeadBucket named the region, so treat it as authoritative only when
        # an in-region HeadBucket also proves access.
        regional_client.head_bucket(Bucket=bucket)
        return regional_client, region


def find_profile_for_bucket(bucket: str, profiles: Sequence[str]) -> str | None:
    """Return the first profile that can read *bucket* in the bucket's region."""
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    for name in profiles:
        try:
            open_bucket_client(bucket, boto3.Session(profile_name=name))
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
    try:
        s3_client, region = open_bucket_client(bucket, session)
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
    new_s3, region = open_bucket_client(bucket, new_session)
    return new_session, new_s3, region, match


QUILT_POLICY_SID = "QuiltCrossAccountAccess"
SNS_PUBLISH_POLICY_SID = "QuiltBucketNotifications"
SNS_SUBSCRIBE_POLICY_SID = "QuiltCrossAccountSNSAccess"
SNS_TOPIC_CONFIG_ID = "QuiltBucketNotifications"

# Statements whose ``Principal.AWS`` list accumulates instead of being replaced.
# A bucket owner prepares a shared bucket for one consuming stack at a time and
# cannot know every other stack that was granted access months earlier, so
# preparation must be additive (issue #102). Deliberate removal is the job of
# ``quiltx bucket revoke``. Every other Sid keeps replace-by-Sid semantics --
# notably the SNS publish statement, which doubles as an ownership marker and is
# compared for exact equality by ``_sns_policy_has_bucket_marker``.
PRINCIPAL_ACCUMULATING_SIDS = frozenset({QUILT_POLICY_SID, SNS_SUBSCRIBE_POLICY_SID})

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


class PolicyConflictError(ValueError):
    """Raised when an existing Quilt statement cannot be safely accumulated onto."""


def _sorted_principals(principals: Any) -> tuple[str, ...]:
    """Return principals in a stable, comparable order for reporting."""
    return tuple(sorted(principals))


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
    bucket_principals_before: tuple[str, ...] = ()
    bucket_principals_after: tuple[str, ...] = ()
    sns_principals_before: tuple[str, ...] = ()
    sns_principals_after: tuple[str, ...] = ()

    @property
    def principals_before(self) -> tuple[str, ...]:
        """Principals the bucket's Quilt statements granted before this plan."""
        return _sorted_principals(
            {*self.bucket_principals_before, *self.sns_principals_before}
        )

    @property
    def principals_after(self) -> tuple[str, ...]:
        """Principals the bucket's Quilt statements grant once applied."""
        return _sorted_principals(
            {*self.bucket_principals_after, *self.sns_principals_after}
        )

    @property
    def principals_added(self) -> tuple[str, ...]:
        """Principals gaining access that no Quilt statement granted before."""
        return _sorted_principals(
            set(self.principals_after) - set(self.principals_before)
        )

    @property
    def principals_removed(self) -> tuple[str, ...]:
        """Principals losing access; empty whenever grants accumulate correctly."""
        return _sorted_principals(
            set(self.principals_before) - set(self.principals_after)
        )

    @property
    def principals_kept(self) -> tuple[str, ...]:
        """Granted principals this run did not request, which accumulation keeps.

        Reporting these keeps an attempted narrowing from looking like a
        success: naming a subset of the current principals does not withdraw the
        rest, because only ``quiltx bucket revoke`` removes access.
        """
        return _sorted_principals(set(self.principals_before) - set(self.principals))

    def handoff(self) -> dict[str, Any]:
        """Return the minimal non-secret handoff for the catalog operator.

        ``principals`` is what this run asked for; ``effective_principals`` is
        what the bucket actually grants once applied. They differ whenever grants
        accumulate, and the operator's record needs the effective set to be
        accurate about who can reach the bucket.
        """
        return {
            "bucket": self.bucket,
            "region": self.region,
            "owning_account": self.owning_account,
            "principals": list(self.principals),
            "effective_principals": list(self.principals_after),
            "sns_topic_arn": self.sns_topic_arn,
        }


@dataclass(frozen=True)
class BucketRevocationPlan:
    """Exact AWS documents that withdraw cross-account Quilt grants on a bucket.

    Revocation is the deliberate counterpart to accumulating preparation: it
    touches only the two principal-bearing Quilt statements and leaves bucket
    notifications and the SNS topic in place, since other stacks may still be
    consuming them.
    """

    bucket: str
    region: str
    owning_account: str
    requested_principals: tuple[str, ...]
    sns_topic_arn: str
    bucket_policy: dict[str, Any] | None
    sns_policy: dict[str, Any] | None
    original_bucket_policy: dict[str, Any] | None
    original_sns_policy: dict[str, Any] | None
    topic_exists: bool
    bucket_policy_changed: bool
    sns_policy_changed: bool
    remove_bucket_policy: bool
    bucket_principals_before: tuple[str, ...] = ()
    bucket_principals_after: tuple[str, ...] = ()
    sns_principals_before: tuple[str, ...] = ()
    sns_principals_after: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """Whether applying this plan would write anything."""
        return self.bucket_policy_changed or self.sns_policy_changed

    @property
    def principals_before(self) -> tuple[str, ...]:
        """Principals the bucket's Quilt statements grant today."""
        return _sorted_principals(
            {*self.bucket_principals_before, *self.sns_principals_before}
        )

    @property
    def principals_after(self) -> tuple[str, ...]:
        """Principals that keep access once this plan is applied."""
        return _sorted_principals(
            {*self.bucket_principals_after, *self.sns_principals_after}
        )

    @property
    def principals_removed(self) -> tuple[str, ...]:
        """Requested principals that actually hold a grant being withdrawn."""
        return _sorted_principals(
            set(self.principals_before) - set(self.principals_after)
        )

    @property
    def principals_not_present(self) -> tuple[str, ...]:
        """Requested principals that hold no Quilt grant to begin with."""
        return _sorted_principals(
            set(self.requested_principals) - set(self.principals_before)
        )

    def handoff(self) -> dict[str, Any]:
        """Return the minimal non-secret summary of what access was withdrawn."""
        return {
            "bucket": self.bucket,
            "region": self.region,
            "owning_account": self.owning_account,
            "principals_removed": list(self.principals_removed),
            "principals_remaining": list(self.principals_after),
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
        principal_value: str | list[str] = _principal_value(principals)
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
    existing: Mapping[str, Any] | None,
    statement: Mapping[str, Any],
    *,
    accumulate_principals: bool = True,
) -> dict[str, Any]:
    """Merge a single statement into a bucket policy document, matched by Sid.

    Statements in :data:`PRINCIPAL_ACCUMULATING_SIDS` keep the principals the
    existing statement already grants and add the requested ones; every other
    Sid is replaced outright. Pass ``accumulate_principals=False`` to write an
    exact principal set, which is what revocation needs.
    """
    if existing is None:
        return {
            "Version": "2012-10-17",
            "Statement": [dict(statement)],
        }

    merged = dict(existing)
    merged["Statement"] = _merge_policy_statements(
        existing.get("Statement"),
        dict(statement),
        accumulate_principals=accumulate_principals,
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


def remove_bucket_policy(bucket: str, s3_client: Any = None) -> None:
    """Delete the bucket policy entirely.

    Needed when revoking the last Quilt principal leaves no statements behind:
    S3 rejects a policy document with an empty ``Statement`` list.
    """
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    s3_client.delete_bucket_policy(Bucket=bucket)


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
    *,
    accumulate_principals: bool = True,
) -> dict[str, Any]:
    """Merge owner and Quilt statements into an SNS policy document.

    The subscribe statement accumulates principals; the publish statement is
    replaced outright because it doubles as the bucket ownership marker.
    """
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
    policy["Statement"] = _merge_policy_statements(
        statements,
        subscribe_statement,
        accumulate_principals=accumulate_principals,
    )
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
            same_topic = (
                key == "TopicConfigurations" and config.get("Id") == SNS_TOPIC_CONFIG_ID
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


def _sns_policy_has_bucket_marker(
    policy: Mapping[str, Any] | None,
    bucket: str,
    sns_topic_arn: str,
    owning_account: str,
) -> bool:
    """Return whether a topic policy proves Quilt ownership for this bucket."""
    if policy is None:
        return False
    expected = _build_sns_topic_publish_policy_statement(
        bucket, sns_topic_arn, owning_account
    )
    statements = policy.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    return any(statement == expected for statement in statements)


def _validate_retained_notification_destinations(
    notification_config: Mapping[str, Any],
    selected_topic_arn: str,
    *,
    sns_client: Any,
    sqs_client: Any | None,
    lambda_client: Any | None,
) -> None:
    """Fail safely when a preserved SNS, SQS, or Lambda destination is stale."""
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

    for config in notification_config.get("QueueConfigurations", []):
        queue_arn = config.get("QueueArn")
        if not queue_arn:
            continue
        if sqs_client is None:
            raise ValueError("sqs_client is required to validate retained SQS queues")
        arn_parts = str(queue_arn).split(":", 5)
        if len(arn_parts) != 6 or arn_parts[2] != "sqs":
            raise NotificationConflictError(
                f"preserved SQS notification {config.get('Id', '<no id>')!r} "
                f"has invalid queue ARN {queue_arn}"
            )
        try:
            sqs_client.get_queue_url(
                QueueName=arn_parts[5], QueueOwnerAWSAccountId=arn_parts[4]
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in {
                "AWS.SimpleQueueService.NonExistentQueue",
                "QueueDoesNotExist",
            }:
                raise
            raise NotificationConflictError(
                f"preserved SQS notification {config.get('Id', '<no id>')!r} "
                f"references missing queue {queue_arn}; remove the stale "
                "notification or recreate that queue before preparing"
            ) from exc

    for config in notification_config.get("LambdaFunctionConfigurations", []):
        function_arn = config.get("LambdaFunctionArn")
        if not function_arn:
            continue
        if lambda_client is None:
            raise ValueError(
                "lambda_client is required to validate retained Lambda functions"
            )
        try:
            lambda_client.get_function_configuration(FunctionName=function_arn)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                raise
            raise NotificationConflictError(
                f"preserved Lambda notification {config.get('Id', '<no id>')!r} "
                f"references missing function {function_arn}; remove the stale "
                "notification or recreate that function before preparing"
            ) from exc


def resolve_principal_list(
    control_account_id: str | None, principals: Sequence[str] | None
) -> tuple[str, ...]:
    """Return the principals to act on, defaulting to the control account root."""
    principal_list = tuple(_dedupe_principals(principals or ()))
    if principal_list:
        return principal_list
    if not control_account_id:
        raise ValueError("provide --control-account-id or at least one --principal")
    return (f"arn:aws:iam::{control_account_id}:root",)


def build_bucket_preparation_plan(
    bucket: str,
    region: str,
    owning_account: str,
    *,
    control_account_id: str | None = None,
    principals: Sequence[str] | None = None,
    s3_client: Any,
    sns_client: Any,
    sqs_client: Any | None = None,
    lambda_client: Any | None = None,
) -> BucketPreparationPlan:
    """Read AWS state and return the exact idempotent preparation plan."""
    principal_list = resolve_principal_list(control_account_id, principals)

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
    if (
        topic_exists
        and existing_topic_arn is None
        and not _sns_policy_has_bucket_marker(
            existing_sns_policy, bucket, sns_topic_arn, owning_account
        )
    ):
        raise NotificationConflictError(
            f"existing topic {sns_topic_arn} lacks a bucket-specific Quilt ownership "
            "marker; rename or remove the colliding topic before preparing"
        )
    _validate_retained_notification_destinations(
        notification_configuration,
        sns_topic_arn,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )
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
        bucket_principals_before=statement_principals(
            _find_policy_statement(existing_bucket_policy, QUILT_POLICY_SID)
        ),
        bucket_principals_after=statement_principals(
            _find_policy_statement(bucket_policy, QUILT_POLICY_SID)
        ),
        sns_principals_before=statement_principals(
            _find_policy_statement(existing_sns_policy, SNS_SUBSCRIBE_POLICY_SID)
        ),
        sns_principals_after=statement_principals(
            _find_policy_statement(sns_policy, SNS_SUBSCRIBE_POLICY_SID)
        ),
    )


def _raise_drift(command: str, *changed: str) -> None:
    raise PreparationDriftError(
        "AWS state changed after planning ("
        + ", ".join(changed)
        + f"); rerun bucket {command} to build a fresh plan"
    )


def _raise_preparation_drift(*changed: str) -> None:
    _raise_drift("prepare", *changed)


def _raise_revocation_drift(*changed: str) -> None:
    _raise_drift("revoke", *changed)


def _assert_bucket_preparation_is_current(
    plan: BucketPreparationPlan,
    *,
    s3_client: Any,
    sns_client: Any,
    sqs_client: Any | None,
    lambda_client: Any | None,
) -> None:
    """Verify every baseline and retained destination before the first write."""
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
        _raise_preparation_drift(*changed)

    _validate_retained_notification_destinations(
        current_notifications,
        plan.sns_topic_arn,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )


def apply_bucket_preparation(
    plan: BucketPreparationPlan,
    *,
    s3_client: Any,
    sns_client: Any,
    sqs_client: Any | None = None,
    lambda_client: Any | None = None,
) -> None:
    """Apply a plan with baseline checks before the first and every later write."""
    _assert_bucket_preparation_is_current(
        plan,
        s3_client=s3_client,
        sns_client=sns_client,
        sqs_client=sqs_client,
        lambda_client=lambda_client,
    )

    if plan.sns_policy_changed:
        expected_sns_policy: dict[str, Any] | None
        if not plan.topic_exists:
            topic_arn = ensure_sns_topic(
                plan.bucket, plan.region, sns_client=sns_client
            )
            if topic_arn != plan.sns_topic_arn:
                raise ValueError(
                    f"created SNS topic ARN {topic_arn!r} differs from planned "
                    f"ARN {plan.sns_topic_arn!r}"
                )
            expected_sns_policy = _build_default_sns_owner_policy(
                plan.sns_topic_arn, plan.owning_account
            )
        else:
            expected_sns_policy = plan.original_sns_policy

        current_topic_exists, current_sns_policy = _sns_policy_if_topic_exists(
            plan.sns_topic_arn, sns_client
        )
        if not current_topic_exists or current_sns_policy != expected_sns_policy:
            _raise_preparation_drift("SNS topic policy")
        apply_sns_topic_policy(
            plan.sns_topic_arn, plan.sns_policy, sns_client=sns_client
        )

    if plan.bucket_policy_changed:
        current_bucket_policy = get_bucket_policy(plan.bucket, s3_client=s3_client)
        if current_bucket_policy != plan.original_bucket_policy:
            _raise_preparation_drift("bucket policy")
        apply_bucket_policy(plan.bucket, plan.bucket_policy, s3_client=s3_client)

    if plan.notification_configuration_changed:
        current_notifications = get_bucket_notification_configuration(
            plan.bucket, s3_client=s3_client
        )
        if current_notifications != plan.original_notification_configuration:
            _raise_preparation_drift("bucket notification configuration")
        _validate_retained_notification_destinations(
            current_notifications,
            plan.sns_topic_arn,
            sns_client=sns_client,
            sqs_client=sqs_client,
            lambda_client=lambda_client,
        )
        s3_client.put_bucket_notification_configuration(
            Bucket=plan.bucket,
            NotificationConfiguration=plan.notification_configuration,
        )


def _planned_principals(
    planned_policy: Mapping[str, Any] | None,
    sid: str,
    unchanged: tuple[str, ...],
) -> tuple[str, ...]:
    """Return the principals *planned_policy* will grant under *sid*.

    ``None`` means no write is planned for that document, so the principals it
    already grants stay in force.
    """
    if planned_policy is None:
        return unchanged
    return statement_principals(_find_policy_statement(planned_policy, sid))


def build_bucket_revocation_plan(
    bucket: str,
    region: str,
    owning_account: str,
    *,
    control_account_id: str | None = None,
    principals: Sequence[str] | None = None,
    s3_client: Any,
    sns_client: Any,
) -> BucketRevocationPlan:
    """Read AWS state and return the plan that withdraws *principals*' access.

    Only the two principal-bearing Quilt statements are rewritten. Principals
    that hold no grant are reported rather than treated as an error, so a repeat
    revoke converges to a no-op.
    """
    principal_list = resolve_principal_list(control_account_id, principals)
    revoked = set(principal_list)

    existing_bucket_policy = get_bucket_policy(bucket, s3_client=s3_client)
    sns_topic_arn = f"arn:aws:sns:{region}:{owning_account}:{_sns_topic_name(bucket)}"
    topic_exists, existing_sns_policy = _sns_policy_if_topic_exists(
        sns_topic_arn, sns_client
    )

    bucket_before = statement_principals(
        _find_policy_statement(existing_bucket_policy, QUILT_POLICY_SID)
    )
    bucket_after = tuple(item for item in bucket_before if item not in revoked)
    sns_before = statement_principals(
        _find_policy_statement(existing_sns_policy, SNS_SUBSCRIBE_POLICY_SID)
    )
    sns_after = tuple(item for item in sns_before if item not in revoked)

    bucket_policy: dict[str, Any] | None = None
    remove_policy = False
    if existing_bucket_policy is not None and bucket_after != bucket_before:
        if bucket_after:
            bucket_policy = merge_bucket_policy(
                existing_bucket_policy,
                build_quilt_policy_statement(bucket, "", principals=bucket_after),
                accumulate_principals=False,
            )
        else:
            bucket_policy = _policy_without_statement(
                existing_bucket_policy, QUILT_POLICY_SID
            )
            remove_policy = bucket_policy is None

    sns_policy: dict[str, Any] | None = None
    if existing_sns_policy is not None and sns_after != sns_before:
        if not _sns_policy_has_bucket_marker(
            existing_sns_policy, bucket, sns_topic_arn, owning_account
        ):
            # Preparation demands this marker before adopting a topic it did not
            # create; revocation must not rewrite an unverified topic policy
            # either. Only a mutation is blocked, so an unrelated topic that
            # happens to share the canonical name cannot stop the S3 grant from
            # being withdrawn.
            raise NotificationConflictError(
                f"topic {sns_topic_arn} lacks a bucket-specific Quilt ownership "
                f"marker for {bucket}, so its policy will not be rewritten; "
                "rename or remove the colliding topic before revoking"
            )
        if sns_after:
            sns_policy = dict(existing_sns_policy)
            sns_policy["Statement"] = _merge_policy_statements(
                existing_sns_policy.get("Statement"),
                _build_sns_topic_subscribe_policy_statement(sns_topic_arn, sns_after),
                accumulate_principals=False,
            )
        else:
            # The owner and publish statements always remain, so dropping the
            # subscribe statement cannot empty the document in practice.
            sns_policy = _policy_without_statement(
                existing_sns_policy, SNS_SUBSCRIBE_POLICY_SID
            )

    bucket_policy_changed = remove_policy or (
        bucket_policy is not None and bucket_policy != existing_bucket_policy
    )
    sns_policy_changed = sns_policy is not None and sns_policy != existing_sns_policy

    return BucketRevocationPlan(
        bucket=bucket,
        region=region,
        owning_account=owning_account,
        requested_principals=principal_list,
        sns_topic_arn=sns_topic_arn,
        bucket_policy=bucket_policy,
        sns_policy=sns_policy,
        original_bucket_policy=existing_bucket_policy,
        original_sns_policy=existing_sns_policy,
        topic_exists=topic_exists,
        bucket_policy_changed=bucket_policy_changed,
        sns_policy_changed=sns_policy_changed,
        remove_bucket_policy=remove_policy,
        bucket_principals_before=bucket_before,
        # Report what the resulting documents will actually grant, not what was
        # requested. A statement that is planned but never written would
        # otherwise be reported as removed, and the JSON handoff would record a
        # withdrawal that never happened.
        bucket_principals_after=(
            ()
            if remove_policy
            else _planned_principals(bucket_policy, QUILT_POLICY_SID, bucket_before)
        ),
        sns_principals_before=sns_before,
        sns_principals_after=_planned_principals(
            sns_policy, SNS_SUBSCRIBE_POLICY_SID, sns_before
        ),
    )


def _assert_bucket_revocation_is_current(
    plan: BucketRevocationPlan,
    *,
    s3_client: Any,
    sns_client: Any,
) -> None:
    """Verify both baselines before the first write.

    Revocation spans two policies but AWS has no cross-service transaction, so
    the only protection against committing half of it is to refuse to start once
    either baseline has moved.
    """
    current_bucket_policy = get_bucket_policy(plan.bucket, s3_client=s3_client)
    current_topic_exists, current_sns_policy = _sns_policy_if_topic_exists(
        plan.sns_topic_arn, sns_client
    )

    changed: list[str] = []
    if current_bucket_policy != plan.original_bucket_policy:
        changed.append("bucket policy")
    if current_topic_exists != plan.topic_exists:
        changed.append("SNS topic existence")
    elif current_sns_policy != plan.original_sns_policy:
        changed.append("SNS topic policy")
    if changed:
        _raise_revocation_drift(*changed)


def apply_bucket_revocation(
    plan: BucketRevocationPlan,
    *,
    s3_client: Any,
    sns_client: Any,
) -> None:
    """Apply a revocation plan, checking every baseline before the first write.

    A revocation that touches both policies can still be interrupted mid-way by
    a failing write, but it cannot start against state that has already drifted.

    The bucket policy is written first, which is the opposite of
    :func:`apply_bucket_preparation`. The order is not arbitrary: it decides
    which half survives an interruption. The S3 statement is the data grant, so
    revoking it first means a failed second write leaves access withdrawn and
    notifications still flowing -- recoverable and visible. Writing SNS first
    would leave the data grant standing, which is the wrong half to keep.
    Preparation has the opposite priority: it grants the topic policy before
    pointing notifications at the topic.
    """
    if not plan.changed:
        return

    _assert_bucket_revocation_is_current(
        plan, s3_client=s3_client, sns_client=sns_client
    )

    if plan.bucket_policy_changed:
        current_bucket_policy = get_bucket_policy(plan.bucket, s3_client=s3_client)
        if current_bucket_policy != plan.original_bucket_policy:
            _raise_revocation_drift("bucket policy")
        if plan.remove_bucket_policy:
            remove_bucket_policy(plan.bucket, s3_client=s3_client)
        elif plan.bucket_policy is not None:
            apply_bucket_policy(plan.bucket, plan.bucket_policy, s3_client=s3_client)

    if plan.sns_policy_changed and plan.sns_policy is not None:
        current_topic_exists, current_sns_policy = _sns_policy_if_topic_exists(
            plan.sns_topic_arn, sns_client
        )
        if not current_topic_exists or current_sns_policy != plan.original_sns_policy:
            _raise_revocation_drift("SNS topic policy")
        apply_sns_topic_policy(
            plan.sns_topic_arn, plan.sns_policy, sns_client=sns_client
        )


def configure_bucket_notifications(
    bucket: str, sns_topic_arn: str, s3_client: Any = None
) -> None:
    """Converge S3 notifications through the shared safe planner."""
    if s3_client is None:
        import boto3

        s3_client = boto3.client("s3")

    existing = get_bucket_notification_configuration(bucket, s3_client=s3_client)
    notification_config = build_bucket_notification_configuration(
        existing, sns_topic_arn
    )
    if notification_config != existing:
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
    bucket_title = title or bucket

    existing = stack.admin.buckets.get(bucket)

    session = boto3.Session(profile_name=profile)
    s3_client = session.client("s3")
    bucket_region = get_bucket_region(bucket, s3_client=s3_client)
    sns_client = session.client("sns", region_name=bucket_region)
    data_account_id = str(session.client("sts").get_caller_identity()["Account"])

    plan = build_bucket_preparation_plan(
        bucket,
        bucket_region,
        data_account_id,
        control_account_id=control_account_id,
        principals=principal_list or None,
        s3_client=s3_client,
        sns_client=sns_client,
    )
    apply_bucket_preparation(plan, s3_client=s3_client, sns_client=sns_client)

    # Register only when the catalog row is absent; preparation always converges.
    if existing is None:
        stack.admin.buckets.add(
            name=bucket,
            title=bucket_title,
            sns_notification_arn=plan.sns_topic_arn,
        )
        result_title = bucket_title
    else:
        result_title = getattr(existing, "title", bucket_title)

    return AddBucketResult(
        bucket=bucket,
        title=result_title,
        sns_topic_arn=plan.sns_topic_arn,
        already_registered=existing is not None,
    )


# --- Live access verification -------------------------------------------------
#
# Registration and search-index state do not prove that the catalog stack can
# read a bucket right now (issue #87): a stale index entry outlives revoked
# access, and an empty or freshly registered bucket has nothing to index. The
# probes below separate the three questions -- is the bucket registered, can the
# catalog stack read it live, and is notification/index wiring delivering.

# Mirrors BucketUpdateInput in the catalog's GraphQL schema. Every field is read
# back from BucketConfig and resubmitted unchanged, so re-validation cannot
# rewrite the bucket's configuration.
BUCKET_UPDATE_INPUT_FIELDS = (
    "title",
    "iconUrl",
    "description",
    "linkedData",
    "overviewUrl",
    "tags",
    "relevanceScore",
    "snsNotificationArn",
    "scannerParallelShardsDepth",
    "skipMetaDataIndexing",
    "fileExtensionsToIndex",
    "indexContentBytes",
    "browsable",
    "prefixes",
)

BUCKET_CONFIG_QUERY = """
query quiltxBucketConfig($name: String!) {
  bucketConfig(name: $name) {
    name
    lastIndexed
    %s
  }
}
""" % ("\n    ".join(BUCKET_UPDATE_INPUT_FIELDS))

BUCKET_REVALIDATE_MUTATION = """
mutation quiltxBucketRevalidate($name: String!, $input: BucketUpdateInput!) {
  bucketUpdate(name: $name, input: $input) {
    __typename
    ... on BucketUpdateSuccess {
      bucketConfig {
        name
      }
    }
    ... on InsufficientPermissions {
      message
    }
  }
}
"""

# Which capability the registry's answer implicates, for error output.
ACCESS_PROBE_CAPABILITIES = {
    "BucketUpdateSuccess": "bucket metadata, listing, and object read",
    "InsufficientPermissions": "S3 read access (ListBucket / GetObject)",
    "NotificationConfigurationError": "bucket notification configuration",
    "NotificationTopicNotFound": "SNS notification topic",
    "SnsInvalid": "SNS notification topic",
    "BucketNotFound": "catalog registration",
}

LIVE_ACCESS_CAPABILITY = "live S3 access"


@dataclass(frozen=True)
class BucketAccessProbe:
    """Result of asking the catalog stack to re-verify live bucket access.

    The catalog re-validates the bucket with the stack's own service identity,
    so the answer describes current S3 access rather than local credentials or
    search-index state.
    """

    bucket: str
    status: str  # "ok" | "failed" | "unavailable"
    capability: str
    detail: str
    principal: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def failed(self) -> bool:
        return self.status == "failed"

    @property
    def unavailable(self) -> bool:
        return self.status == "unavailable"


def _admin_graphql(query: str, variables: Mapping[str, Any]) -> Mapping[str, Any]:
    from quiltx import quilt3_facade

    return quilt3_facade.admin_graphql(query, variables)


def read_bucket_config(bucket: str, *, graphql: Any = None) -> dict[str, Any] | None:
    """Return the catalog's full configuration for *bucket*, or None if absent."""
    run = graphql or _admin_graphql
    data = run(BUCKET_CONFIG_QUERY, {"name": bucket})
    config = (data or {}).get("bucketConfig")
    return dict(config) if config else None


def probe_bucket_access(
    stack: stack_lib.Catalog,
    bucket: str,
    *,
    principal: str | None = None,
    graphql: Any = None,
) -> BucketAccessProbe:
    """Ask the catalog stack to re-verify live access to *bucket*.

    Reads the bucket's complete catalog configuration and resubmits it
    unchanged. The registry validates S3 and SNS access with the stack's own
    identity while handling that mutation, which makes its answer a live
    access probe: an empty bucket passes, and revoked access fails even when
    stale search-index entries remain.

    A catalog that cannot answer either operation yields ``status
    "unavailable"`` so callers can fall back instead of reporting a failure.
    """
    stack.ensure_auth()
    run = graphql or _admin_graphql

    try:
        config = read_bucket_config(bucket, graphql=run)
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        return BucketAccessProbe(
            bucket=bucket,
            status="unavailable",
            capability=LIVE_ACCESS_CAPABILITY,
            detail=f"catalog did not answer the bucketConfig query: {exc}",
            principal=principal,
        )

    if config is None:
        return BucketAccessProbe(
            bucket=bucket,
            status="failed",
            capability="catalog registration",
            detail=f"{bucket} is not registered in Quilt",
            principal=principal,
        )

    payload = {field: config.get(field) for field in BUCKET_UPDATE_INPUT_FIELDS}
    try:
        data = run(BUCKET_REVALIDATE_MUTATION, {"name": bucket, "input": payload})
    except Exception as exc:
        if stack_lib.is_auth_error(exc):
            raise
        return BucketAccessProbe(
            bucket=bucket,
            status="unavailable",
            capability=LIVE_ACCESS_CAPABILITY,
            detail=f"catalog did not re-validate the bucket: {exc}",
            principal=principal,
        )

    result = (data or {}).get("bucketUpdate") or {}
    typename = str(result.get("__typename") or "")
    capability = ACCESS_PROBE_CAPABILITIES.get(typename, LIVE_ACCESS_CAPABILITY)
    if typename == "BucketUpdateSuccess":
        return BucketAccessProbe(
            bucket=bucket,
            status="ok",
            capability=capability,
            detail="catalog stack re-validated the bucket with its own identity",
            principal=principal,
        )

    message = str(result.get("message") or "").strip()
    if message:
        detail = f"{typename}: {message}"
    elif typename:
        detail = typename
    else:
        detail = f"unexpected bucketUpdate response {result!r}"
    return BucketAccessProbe(
        bucket=bucket,
        status="failed",
        capability=capability,
        detail=detail,
        principal=principal,
    )


# --- Pre-registration grant checks -------------------------------------------
#
# A cross-account grant handed back by ``bucket prepare`` is fully checkable
# before the catalog row exists (issue #92). These checks run from the control
# account so a wrong-account grant surfaces at handoff time instead of as an
# opaque AccessDenied inside ``catalog acl``.

GRANT_SNS_ACTIONS = ("sns:GetTopicAttributes", "sns:Subscribe")


@dataclass(frozen=True)
class GrantCheck:
    """One capability checked against a bucket from the control account."""

    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class BucketGrantReport:
    """Control-account view of a bucket grant, with the principal that probed it."""

    bucket: str
    principal: str | None
    account_id: str | None
    region: str | None
    checks: tuple[GrantCheck, ...]

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(check.ok for check in self.checks)


def _aws_error_detail(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            code = str(error.get("Code") or "").strip()
            message = str(error.get("Message") or "").strip()
            if code and message:
                return f"{code}: {message}"
            if code:
                return code
    return str(exc)


def _normalized_principal(principal: str | None) -> str | None:
    """Map an assumed-role session ARN back to the role ARN policies name.

    ``sts:GetCallerIdentity`` answers
    ``arn:aws:sts::123:assumed-role/Role/session`` while policies name
    ``arn:aws:iam::123:role/Role``. Any ARN shape that does not parse cleanly is
    returned unchanged rather than rewritten into a guess.
    """
    if not principal:
        return None
    parts = principal.split(":")
    if len(parts) != 6 or parts[2] != "sts":
        return principal
    resource = parts[5].split("/")
    if len(resource) < 2 or resource[0] != "assumed-role" or not resource[1]:
        return principal
    return f"arn:aws:iam::{parts[4]}:role/{resource[1]}"


def _statement_principals(statement: Mapping[str, Any]) -> list[str]:
    principal = statement.get("Principal")
    if principal is None:
        return []
    if isinstance(principal, Mapping):
        aws = principal.get("AWS")
    else:
        aws = principal
    if aws is None:
        return []
    if isinstance(aws, str):
        return [aws]
    return [str(item) for item in aws]


def _statement_matches_principal(
    statement: Mapping[str, Any], principal: str | None, account_id: str | None
) -> bool:
    candidates = {value for value in (_normalized_principal(principal),) if value}
    if account_id:
        candidates.add(account_id)
        candidates.add(f"arn:aws:iam::{account_id}:root")
    for value in _statement_principals(statement):
        if value == "*" or value in candidates:
            return True
    return False


def _statement_actions(statement: Mapping[str, Any]) -> set[str]:
    actions = statement.get("Action")
    if actions is None:
        return set()
    if isinstance(actions, str):
        actions = [actions]
    return {str(action).lower() for action in actions}


@dataclass(frozen=True)
class SnsPolicyEvaluation:
    """Static reading of an SNS topic policy for one principal.

    ``conditional`` holds actions that only a condition-bearing statement
    allows. Conditions are not evaluated, so those actions are reported apart
    from ``granted`` rather than assumed to apply -- the canonical SNS owner
    statement, for instance, allows Subscribe only to the topic owner.
    """

    granted: frozenset[str]
    denied: frozenset[str]
    conditional: frozenset[str]

    def missing(self, actions: Sequence[str]) -> list[str]:
        return [action for action in actions if action not in self.granted]


def _statement_covers_actions(
    statement: Mapping[str, Any], actions: Sequence[str]
) -> set[str]:
    listed = _statement_actions(statement)
    covered: set[str] = set()
    for action in actions:
        lowered = action.lower()
        service = lowered.split(":", 1)[0]
        if listed & {"*", f"{service}:*", lowered}:
            covered.add(action)
    return covered


def evaluate_sns_policy(
    policy: Mapping[str, Any] | None,
    actions: Sequence[str],
    *,
    principal: str | None,
    account_id: str | None,
    topic_arn: str,
) -> SnsPolicyEvaluation:
    """Read which *actions* an SNS topic policy allows for this principal.

    An explicit ``Deny`` overrides any allow, matching IAM evaluation. Only
    unconditional allows count as granted; ``NotPrincipal`` and ``NotAction``
    are not interpreted, so a policy using them is read conservatively.
    """
    if not policy:
        return SnsPolicyEvaluation(frozenset(), frozenset(), frozenset())
    statements = policy.get("Statement") or []
    if isinstance(statements, Mapping):
        statements = [statements]

    granted: set[str] = set()
    denied: set[str] = set()
    conditional: set[str] = set()
    for statement in statements:
        if not isinstance(statement, Mapping):
            continue
        # Casefold the effect so an oddly-spelled Deny is still honored rather
        # than silently skipped, which would over-report access.
        effect = str(statement.get("Effect", "Allow")).strip().lower()
        if effect not in {"allow", "deny"}:
            continue
        resources = statement.get("Resource")
        if isinstance(resources, str):
            resources = [resources]
        if resources and topic_arn not in resources and "*" not in resources:
            continue
        if not _statement_matches_principal(statement, principal, account_id):
            continue
        covered = _statement_covers_actions(statement, actions)
        if not covered:
            continue
        if effect == "deny":
            # A conditional deny may not apply, but treating it as binding is
            # the safe reading: the probe under-reports access rather than
            # promising a grant AWS refuses.
            denied |= covered
        elif statement.get("Condition"):
            conditional |= covered
        else:
            granted |= covered

    return SnsPolicyEvaluation(
        granted=frozenset(granted - denied),
        denied=frozenset(denied),
        conditional=frozenset(conditional - denied),
    )


def _sns_grant_detail(
    evaluation: SnsPolicyEvaluation,
    *,
    principal: str | None,
    account_id: str | None,
) -> str:
    """Explain an SNS policy reading in terms an operator can act on."""
    who = principal or account_id or "this principal"
    missing = evaluation.missing(GRANT_SNS_ACTIONS)
    if not missing:
        return f"topic policy allows {', '.join(GRANT_SNS_ACTIONS)} for {who}"

    reasons: list[str] = []
    denied = [action for action in missing if action in evaluation.denied]
    if denied:
        reasons.append(f"explicitly denied: {', '.join(denied)}")
    conditional = [action for action in missing if action in evaluation.conditional]
    if conditional:
        reasons.append(
            f"allowed only under conditions quiltx does not evaluate: "
            f"{', '.join(conditional)}"
        )
    absent = [
        action
        for action in missing
        if action not in evaluation.denied and action not in evaluation.conditional
    ]
    if absent:
        reasons.append(f"not allowed: {', '.join(absent)}")
    return f"topic policy for {who}: " + "; ".join(reasons)


def _first_notification_topic(notification_config: Mapping[str, Any]) -> str | None:
    for config in notification_config.get("TopicConfigurations", []):
        topic_arn = config.get("TopicArn")
        if topic_arn and _has_object_notification_event(config.get("Events") or []):
            return str(topic_arn)
    return None


def _arn_region(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[3] if len(parts) > 5 and parts[3] else None


def probe_bucket_grant(
    bucket: str,
    *,
    session: Any,
    expected_account_id: str | None = None,
) -> BucketGrantReport:
    """Check a bucket grant from the control account, before registration.

    Reports the principal that ran the checks so a grant issued to the wrong
    account is identified at the handoff instead of surfacing later as an
    opaque ``AccessDenied``.
    """
    from botocore.exceptions import BotoCoreError

    checks: list[GrantCheck] = []
    principal: str | None = None
    account_id: str | None = None
    region: str | None = None

    try:
        identity = session.client("sts").get_caller_identity()
        principal = str(identity.get("Arn") or "") or None
        account_id = str(identity.get("Account") or "") or None
        checks.append(
            GrantCheck(
                "probing principal (sts:GetCallerIdentity)",
                True,
                principal or f"account {account_id}",
            )
        )
    except (ClientError, BotoCoreError) as exc:
        checks.append(
            GrantCheck(
                "probing principal (sts:GetCallerIdentity)",
                False,
                _aws_error_detail(exc),
            )
        )

    if expected_account_id:
        matched = account_id == expected_account_id
        checks.append(
            GrantCheck(
                "control account match",
                matched,
                (
                    f"probing in the Quilt control account {expected_account_id}"
                    if matched
                    else (
                        f"probe ran in account {account_id or 'unknown'}, but the "
                        f"catalog's control account is {expected_account_id}"
                    )
                ),
            )
        )

    s3_client: Any = None
    try:
        s3_client, region = open_bucket_client(bucket, session)
        checks.append(
            GrantCheck(
                "bucket reachable (s3:GetBucketLocation)", True, f"region {region}"
            )
        )
    except (ClientError, BotoCoreError) as exc:
        checks.append(
            GrantCheck(
                "bucket reachable (s3:GetBucketLocation)",
                False,
                _aws_error_detail(exc),
            )
        )

    topic_arn: str | None = None
    if s3_client is not None:
        try:
            listing = s3_client.list_objects_v2(Bucket=bucket, MaxKeys=1)
            empty = not int(listing.get("KeyCount") or 0)
            checks.append(
                GrantCheck(
                    "list bucket (s3:ListBucket)",
                    True,
                    (
                        "bucket is empty; access is still valid"
                        if empty
                        else "listing returned an object"
                    ),
                )
            )
        except (ClientError, BotoCoreError) as exc:
            checks.append(
                GrantCheck("list bucket (s3:ListBucket)", False, _aws_error_detail(exc))
            )

        try:
            notifications = get_bucket_notification_configuration(
                bucket, s3_client=s3_client
            )
            topic_arn = _existing_notification_topic(
                notifications
            ) or _first_notification_topic(notifications)
            checks.append(
                GrantCheck(
                    "read notifications (s3:GetBucketNotification)",
                    bool(topic_arn),
                    (
                        f"object notifications publish to {topic_arn}"
                        if topic_arn
                        else (
                            "no SNS topic receives object-create/remove events; run "
                            "`quiltx bucket prepare` in the data account first"
                        )
                    ),
                )
            )
        except (ClientError, BotoCoreError) as exc:
            checks.append(
                GrantCheck(
                    "read notifications (s3:GetBucketNotification)",
                    False,
                    _aws_error_detail(exc),
                )
            )

    if topic_arn:
        try:
            sns_client = session.client(
                "sns", region_name=_arn_region(topic_arn) or region
            )
            attributes = sns_client.get_topic_attributes(TopicArn=topic_arn).get(
                "Attributes", {}
            )
            checks.append(
                GrantCheck(
                    "read SNS topic (sns:GetTopicAttributes)", True, str(topic_arn)
                )
            )
            evaluation = evaluate_sns_policy(
                _parse_json_document(attributes.get("Policy")),
                GRANT_SNS_ACTIONS,
                principal=principal,
                account_id=account_id,
                topic_arn=topic_arn,
            )
            checks.append(
                GrantCheck(
                    "SNS topic policy grants subscribe",
                    not evaluation.missing(GRANT_SNS_ACTIONS),
                    _sns_grant_detail(
                        evaluation, principal=principal, account_id=account_id
                    ),
                )
            )
        except (ClientError, BotoCoreError) as exc:
            checks.append(
                GrantCheck(
                    "read SNS topic (sns:GetTopicAttributes)",
                    False,
                    _aws_error_detail(exc),
                )
            )

    return BucketGrantReport(
        bucket=bucket,
        principal=principal,
        account_id=account_id,
        region=region,
        checks=tuple(checks),
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


def statement_principals(statement: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Return a statement's ``Principal.AWS`` entries in document order.

    AWS renders a lone principal as a bare string and several as a list, so both
    shapes must be accepted wherever principals are compared or accumulated.
    """
    if not statement:
        return ()
    principal = statement.get("Principal")
    if isinstance(principal, Mapping):
        aws_principal = principal.get("AWS")
    elif isinstance(principal, str):
        aws_principal = principal
    else:
        aws_principal = None
    if aws_principal is None:
        return ()
    if isinstance(aws_principal, str):
        return (aws_principal,)
    return tuple(str(item) for item in aws_principal)


def _dedupe_principals(principals: Sequence[str]) -> list[str]:
    """Drop duplicates while keeping first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for principal in principals:
        if principal not in seen:
            seen.add(principal)
            ordered.append(principal)
    return ordered


def _principal_value(principals: Sequence[str]) -> str | list[str]:
    """Render principals the way AWS does: a bare string for one, else a list.

    Deduplicates first. A repeated ``--principal`` would otherwise be written
    verbatim on the first insert and collapsed on the next run, so an unchanged
    request would produce a second write instead of the documented no-op.
    """
    values = _dedupe_principals(principals)
    return values[0] if len(values) == 1 else values


def _assert_statement_is_accumulable(existing: Mapping[str, Any], sid: Any) -> None:
    """Refuse to accumulate onto a statement whose meaning that would change.

    Accumulation keeps the existing principals but takes every other field from
    the freshly built statement. Two existing statements make that unsafe:

    * ``Effect: Deny`` would silently become ``Allow``, inverting a deliberate
      lockdown into a grant.
    * a ``*`` principal would be carried into the new statement, so a bucket
      exposed under this Sid stays exposed -- and because Quilt's actions include
      ``s3:PutObject`` and ``s3:DeleteObject``, ``Allow *`` is world-writable.

    Neither is recoverable with ``bucket revoke``, which only removes named IAM
    ARNs, so this fails loudly and leaves the decision to the operator.
    """
    effect = existing.get("Effect")
    if effect is not None and effect != "Allow":
        raise PolicyConflictError(
            f"existing statement {sid!r} has Effect {effect!r}, not 'Allow'; "
            "accumulating Quilt principals onto it would flip its meaning. "
            "Remove or rename that statement by hand before preparing"
        )
    wildcards = [
        principal for principal in statement_principals(existing) if "*" in principal
    ]
    if wildcards:
        raise PolicyConflictError(
            f"existing statement {sid!r} grants wildcard principal "
            f"{', '.join(wildcards)}; accumulating would preserve public access "
            "to Quilt's read/write actions. Remove or rename that statement by "
            "hand before preparing"
        )


def _statement_with_accumulated_principals(
    existing: Mapping[str, Any], statement: Mapping[str, Any]
) -> dict[str, Any]:
    """Return *statement* with the principals *existing* already grants preserved.

    Existing principals keep their document order and newly requested ones are
    appended, so re-running preparation with the same inputs rewrites nothing.
    """
    accumulated = dict(statement)
    principal = statement.get("Principal")
    updated_principal = dict(principal) if isinstance(principal, Mapping) else {}
    updated_principal["AWS"] = _principal_value(
        [*statement_principals(existing), *statement_principals(statement)]
    )
    accumulated["Principal"] = updated_principal
    return accumulated


def _normalize_policy_statements(existing_statements: Any) -> list[dict[str, Any]]:
    """Coerce a policy ``Statement`` value into a list of statement mappings."""
    if existing_statements is None:
        return []
    if isinstance(existing_statements, Mapping):
        return [dict(existing_statements)]
    return [dict(item) for item in existing_statements if isinstance(item, Mapping)]


def _find_policy_statement(
    policy: Mapping[str, Any] | None, sid: str
) -> dict[str, Any] | None:
    """Return the statement in *policy* carrying *sid*, if any."""
    if not policy:
        return None
    for statement in _normalize_policy_statements(policy.get("Statement")):
        if statement.get("Sid") == sid:
            return statement
    return None


def _policy_without_statement(
    policy: Mapping[str, Any], sid: str
) -> dict[str, Any] | None:
    """Drop the statement carrying *sid*; return None when nothing would remain.

    AWS rejects a policy document with an empty ``Statement`` list, so callers
    must delete the policy outright rather than write an empty one.
    """
    remaining = [
        statement
        for statement in _normalize_policy_statements(policy.get("Statement"))
        if statement.get("Sid") != sid
    ]
    if not remaining:
        return None
    updated = dict(policy)
    updated["Statement"] = remaining
    return updated


def _merge_policy_statements(
    existing_statements: Any,
    statement: dict[str, Any],
    *,
    accumulate_principals: bool = True,
) -> list[dict[str, Any]]:
    if existing_statements is None:
        return [statement]
    statements = _normalize_policy_statements(existing_statements)

    sid = statement.get("Sid")
    accumulate = accumulate_principals and sid in PRINCIPAL_ACCUMULATING_SIDS
    replaced = False
    for idx, existing in enumerate(statements):
        if existing.get("Sid") == sid:
            if accumulate:
                _assert_statement_is_accumulable(existing, sid)
                statements[idx] = _statement_with_accumulated_principals(
                    existing, statement
                )
            else:
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
        principal_value = _principal_value(control_principals)
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
