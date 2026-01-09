# EventBridge Tools Specification

## Overview

This document specifies the implementation of EventBridge-related tools for the quiltx CLI toolkit. These tools port functionality from the `251230-eventbridge` project into the unified quiltx CLI.

## Background

The EventBridge infrastructure enables S3 event routing to Quilt's data catalog through two parallel systems:

1. **Manifest Indexing Flow**: S3 → SNS → IndexerQueue → SearchHandler → ManifestIndexerQueue → ManifestIndexer → Elasticsearch
2. **EventBridge Flow**: S3 → SNS → S3SNSToEventBridgeQueue → S3SNSToEventBridge → EventBridge → {EsIngest|Iceberg|Packager}

**Critical Constraint**: ManifestIndexerQueue must NEVER receive direct SNS subscriptions or EventBridge rule targets. Events flow through SearchHandler for intelligent routing.

## Source Material

### Files to Port
1. `test/eventbridge-routing.sh` (117 lines) - Initial EventBridge setup
2. `test/eventbridge-rule.py` (244 lines) - EventBridge rule management
3. `bin/test_bucket_indexing.py` (2,915 lines) - Infrastructure validation

### Key Validation Checks (20+ checks)
From `test_bucket_indexing.py`:
- Stack drift detection
- S3 EventBridge configuration
- SNS topic existence and permissions
- SQS subscriptions and policies
- Lambda functions, event sources, permissions
- Event routing architecture validation
- EventBridge rules and targets
- DLQ health monitoring
- Elasticsearch indices
- IAM policies
- Glue partitions
- Optional end-to-end search testing

## Architecture

### New Library Module: `quiltx/eventbridge.py`

Shared library functions for EventBridge operations:

```python
"""EventBridge infrastructure management and validation."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any
import boto3

# Status types
class CheckStatus(Enum):
    """Status of an infrastructure check"""
    PASS = "✅"
    FAIL = "❌"
    WARN = "⚠️"
    SKIP = "⏭️"

@dataclass
class CheckResult:
    """Result of a single infrastructure check"""
    name: str
    status: CheckStatus
    message: str
    impact: Optional[str] = None
    fix: Optional[str] = None

# Stack resource discovery
def discover_stack_resources(cfn_client, stack_name: str) -> Dict[str, Any]:
    """Discover queue URLs, Lambda ARNs, and other resources from CloudFormation stack."""
    pass

# EventBridge operations
def create_eventbridge_rule(
    events_client,
    rule_name: str,
    bucket_names: List[str],
    topic_arn: str,
    role_arn: str
) -> None:
    """Create EventBridge rule with Input Transformer for S3 events."""
    pass

def create_input_transformer() -> Dict[str, Any]:
    """Create Input Transformer configuration to convert EventBridge format to S3 Records format."""
    pass

def get_existing_rule_buckets(events_client, rule_name: str) -> List[str]:
    """Get list of buckets currently monitored by an EventBridge rule."""
    pass

# IAM operations
def create_eventbridge_iam_role(
    iam_client,
    account_id: str,
    role_name: str,
    topic_arn: str
) -> str:
    """Create IAM role for EventBridge with SNS publish permissions."""
    pass

# SNS operations
def create_sns_topic(sns_client, topic_name: str, region: str) -> str:
    """Create SNS topic and return ARN."""
    pass

def subscribe_queue_to_topic(
    sns_client,
    topic_arn: str,
    queue_arn: str
) -> str:
    """Subscribe SQS queue to SNS topic."""
    pass

def list_topic_subscriptions(sns_client, topic_arn: str) -> List[Dict[str, Any]]:
    """List all subscriptions for an SNS topic."""
    pass

# S3 operations
def enable_eventbridge_on_bucket(s3_client, bucket_name: str) -> None:
    """Enable EventBridge notifications on S3 bucket."""
    pass

def check_eventbridge_enabled(s3_client, bucket_name: str) -> bool:
    """Check if EventBridge is enabled on S3 bucket."""
    pass

def get_bucket_region(s3_client, bucket_name: str) -> str:
    """Get the region of an S3 bucket."""
    pass

# SQS operations
def queue_url_to_arn(queue_url: str, region: str, account_id: str) -> str:
    """Convert SQS queue URL to ARN."""
    pass

def generate_cross_region_policy(queue_arn: str, topic_arn: str) -> Dict[str, Any]:
    """Generate SQS queue policy statement for cross-region SNS access."""
    pass

# Validation functions
def validate_stack_drift(cfn_client, stack_name: str, timeout: int = 0) -> CheckResult:
    """Validate CloudFormation stack drift."""
    pass

def validate_s3_notifications(s3_client, bucket_name: str) -> CheckResult:
    """Validate S3 bucket EventBridge configuration."""
    pass

def validate_sns_topic(sns_client, topic_arn: Optional[str]) -> CheckResult:
    """Validate SNS topic exists and is accessible."""
    pass

def validate_sqs_subscriptions(
    sns_client,
    topic_arn: str,
    expected_queues: Dict[str, Optional[str]]
) -> CheckResult:
    """Validate SQS subscriptions to SNS topic."""
    pass

def validate_sqs_policies(
    sqs_client,
    queue_urls: List[str],
    topic_arn: str,
    bucket_region: str,
    stack_region: str
) -> CheckResult:
    """Validate SQS queue policies allow SNS to send messages."""
    pass

def validate_lambda_event_source(
    lambda_client,
    function_arn: str,
    queue_arn: str
) -> CheckResult:
    """Validate Lambda has event source mapping from SQS queue."""
    pass

def validate_lambda_permissions(
    lambda_client,
    function_name: str,
    queue_arn: str
) -> CheckResult:
    """Validate Lambda has SQS invoke permissions."""
    pass

def validate_event_routing_architecture(
    sns_client,
    sqs_client,
    config: Dict[str, Any]
) -> CheckResult:
    """Validate event routing architecture (critical: no direct ManifestIndexerQueue subscriptions)."""
    pass

def validate_eventbridge_rules(
    events_client,
    config: Dict[str, Any]
) -> CheckResult:
    """Validate EventBridge rules configuration and targets."""
    pass

def validate_dlq_health(sqs_client, dlq_urls: List[str]) -> CheckResult:
    """Validate dead letter queue health (message counts)."""
    pass

def validate_elasticsearch_indices(
    es_endpoint: str,
    required_indices: List[str]
) -> CheckResult:
    """Validate Elasticsearch indices exist."""
    pass
```

## Tool 1: `quiltx eventbridge-setup`

### Purpose
Initial EventBridge setup for a bucket.

### Usage
```bash
# Auto-discover stack from catalog config
quiltx eventbridge-setup --bucket my-bucket

# Explicit stack name
quiltx eventbridge-setup --bucket my-bucket --stack-name quilt-stack

# Explicit region
quiltx eventbridge-setup --bucket my-bucket --region us-west-2

# Non-interactive mode
quiltx eventbridge-setup --bucket my-bucket --yes
```

### Functionality
1. Discover stack resources (queues, topic)
2. Create SNS topic for EventBridge notifications (if doesn't exist)
3. Enable EventBridge on S3 bucket
4. Subscribe Quilt queues to SNS topic:
   - IndexerQueue
   - PkgEventsQueue
   - S3SNSToEventBridgeQueue
5. Detect cross-region setup and generate queue policies
6. Display setup instructions and console URLs

### Implementation: `quiltx/tools/eventbridge_setup.py`

```python
"""EventBridge setup tool for S3 buckets."""
from __future__ import annotations
import argparse
import sys
import boto3
from rich.console import Console
from rich.panel import Panel
from quiltx import configured_catalog, stack, eventbridge

console = Console()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Setup EventBridge routing for S3 bucket to Quilt infrastructure"
    )
    parser.add_argument(
        "--bucket",
        required=True,
        help="S3 bucket name to configure"
    )
    parser.add_argument(
        "--stack-name",
        help="CloudFormation stack name (auto-discovers if not provided)"
    )
    parser.add_argument(
        "--region",
        help="AWS region (defaults to bucket region)"
    )
    parser.add_argument(
        "--topic-name",
        default="quilt-eventbridge-notifications",
        help="SNS topic name (default: quilt-eventbridge-notifications)"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompts"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        # Get bucket region
        s3 = boto3.client('s3')
        bucket_region = eventbridge.get_bucket_region(s3, args.bucket)
        region = args.region or bucket_region

        console.print(f"[bold]EventBridge Setup for {args.bucket}[/bold]")
        console.print(f"Bucket region: {bucket_region}")

        # Discover stack
        if not args.stack_name:
            catalog_url = configured_catalog()
            # Use existing stack discovery logic
            cfn = boto3.client('cloudformation', region_name=region)
            stack_info = stack.find_matching_stack(cfn, catalog_url)
            stack_name = stack_info['StackName']
        else:
            stack_name = args.stack_name

        console.print(f"Stack: {stack_name}")
        console.print(f"Stack region: {region}")

        # Initialize AWS clients
        sns = boto3.client('sns', region_name=bucket_region)
        sqs = boto3.client('sqs', region_name=region)
        cfn = boto3.client('cloudformation', region_name=region)
        sts = boto3.client('sts')

        account_id = sts.get_caller_identity()['Account']
        topic_arn = f"arn:aws:sns:{bucket_region}:{account_id}:{args.topic_name}"

        # Discover stack resources
        config = eventbridge.discover_stack_resources(cfn, stack_name)

        # Create SNS topic
        console.print(f"\n[bold]Creating SNS topic...[/bold]")
        eventbridge.create_sns_topic(sns, args.topic_name, bucket_region)
        console.print(f"[green]✓[/green] Topic: {topic_arn}")

        # Enable EventBridge on bucket
        console.print(f"\n[bold]Enabling EventBridge on bucket...[/bold]")
        eventbridge.enable_eventbridge_on_bucket(s3, args.bucket)
        console.print(f"[green]✓[/green] EventBridge enabled on {args.bucket}")

        # Subscribe queues
        console.print(f"\n[bold]Subscribing queues to SNS topic...[/bold]")
        for queue_name in ['IndexerQueue', 'PkgEventsQueue', 'S3SNSToEventBridgeQueue']:
            queue_url = config.get(f'{queue_name.lower()}_url')
            if queue_url:
                queue_arn = eventbridge.queue_url_to_arn(queue_url, region, account_id)
                eventbridge.subscribe_queue_to_topic(sns, topic_arn, queue_arn)
                console.print(f"[green]✓[/green] Subscribed {queue_name}")

        # Check for cross-region setup
        if bucket_region != region:
            console.print(f"\n[yellow]⚠️  Cross-region setup detected[/yellow]")
            console.print(f"You must update SQS queue policies manually.")
            console.print(f"\nGenerated policies:")

            for queue_name in ['IndexerQueue', 'PkgEventsQueue', 'S3SNSToEventBridgeQueue']:
                queue_url = config.get(f'{queue_name.lower()}_url')
                if queue_url:
                    queue_arn = eventbridge.queue_url_to_arn(queue_url, region, account_id)
                    policy = eventbridge.generate_cross_region_policy(queue_arn, topic_arn)
                    console.print(Panel(
                        f"Queue: {queue_name}\n\n{json.dumps(policy, indent=2)}",
                        title=queue_name,
                        border_style="yellow"
                    ))

        console.print(f"\n[bold green]✓ Setup complete![/bold green]")
        console.print(f"\nNext steps:")
        console.print(f"1. Run: quiltx eventbridge-rule {args.bucket}")
        console.print(f"2. Validate: quiltx validate-infra --bucket {args.bucket}")

        return 0

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
```

### Output Format
Rich formatted with:
- Status indicators (✓, ⚠️, ✗)
- Color-coded sections
- Panels for policies
- Clear next steps

## Tool 2: `quiltx eventbridge-rule`

### Purpose
Create/update EventBridge rules for S3 events.

### Usage
```bash
# Create rule for bucket
quiltx eventbridge-rule my-bucket

# Specify rule name
quiltx eventbridge-rule my-bucket --rule-name custom-rule

# Test with file upload
quiltx eventbridge-rule my-bucket --test

# Non-interactive mode
quiltx eventbridge-rule my-bucket --yes
```

### Functionality
1. Get bucket region
2. Check for existing EventBridge rule
3. If rule exists with different buckets:
   - Interactive prompt: Add/Replace/Abort
4. Create IAM role for EventBridge → SNS
5. Create/update EventBridge rule with Input Transformer
6. Configure Input Transformer to map EventBridge format → S3 Records format
7. Verify bucket EventBridge configuration
8. List SNS topic subscriptions
9. Optional: Upload test file

### Implementation: `quiltx/tools/eventbridge_rule.py`

```python
"""EventBridge rule management tool."""
from __future__ import annotations
import argparse
import sys
import json
import time
import boto3
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from quiltx import eventbridge

console = Console()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create EventBridge rule with Input Transformer for S3 events"
    )
    parser.add_argument(
        "bucket",
        help="S3 bucket name"
    )
    parser.add_argument(
        "--rule-name",
        default="quilt-s3-events-rule",
        help="EventBridge rule name (default: quilt-s3-events-rule)"
    )
    parser.add_argument(
        "--topic-name",
        default="quilt-eventbridge-notifications",
        help="SNS topic name (default: quilt-eventbridge-notifications)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Upload test file to verify setup"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompts"
    )
    return parser

def determine_buckets_to_monitor(
    events_client,
    rule_name: str,
    new_bucket: str,
    interactive: bool
) -> List[str]:
    """Determine which buckets should be monitored based on existing rule."""
    existing_buckets = eventbridge.get_existing_rule_buckets(events_client, rule_name)

    if not existing_buckets:
        return [new_bucket]

    if new_bucket in existing_buckets:
        console.print(f"Rule already monitors '{new_bucket}'")
        return existing_buckets

    # Rule exists with different bucket(s)
    console.print(f"\n[yellow]⚠️  Rule already monitors: {', '.join(existing_buckets)}[/yellow]")

    if not interactive:
        # Default to adding in non-interactive mode
        return existing_buckets + [new_bucket]

    # Interactive prompt
    console.print("\nOptions:")
    console.print("  1) Add to existing (monitor all)")
    console.print(f"  2) Replace with '{new_bucket}' only")
    console.print("  3) Abort")

    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")

    if choice == "1":
        return existing_buckets + [new_bucket]
    elif choice == "2":
        return [new_bucket]
    else:
        console.print("Aborted")
        sys.exit(0)

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        # Get bucket region
        s3 = boto3.client('s3')
        bucket_region = eventbridge.get_bucket_region(s3, args.bucket)

        # Initialize AWS clients
        events = boto3.client('events', region_name=bucket_region)
        sns = boto3.client('sns', region_name=bucket_region)
        iam = boto3.client('iam')
        sts = boto3.client('sts')

        account_id = sts.get_caller_identity()['Account']
        topic_arn = f"arn:aws:sns:{bucket_region}:{account_id}:{args.topic_name}"

        console.print(f"[bold]EventBridge Rule Configuration[/bold]")
        console.print(f"Bucket: {args.bucket}")
        console.print(f"Region: {bucket_region}")
        console.print(f"Topic: {topic_arn}")

        # Create IAM role
        console.print(f"\n[bold]Creating IAM role...[/bold]")
        role_name = f"{args.rule_name}-role"
        role_arn = eventbridge.create_eventbridge_iam_role(
            iam, account_id, role_name, topic_arn
        )
        console.print(f"[green]✓[/green] Role: {role_arn}")

        # Determine buckets to monitor
        buckets_to_monitor = determine_buckets_to_monitor(
            events, args.rule_name, args.bucket, not args.yes
        )

        # Create/update rule
        console.print(f"\n[bold]Creating EventBridge rule...[/bold]")
        eventbridge.create_eventbridge_rule(
            events, args.rule_name, buckets_to_monitor, topic_arn, role_arn
        )
        console.print(f"[green]✓[/green] Rule configured for: {', '.join(buckets_to_monitor)}")

        # Verify bucket configuration
        console.print(f"\n[bold]Verifying bucket configuration...[/bold]")
        if eventbridge.check_eventbridge_enabled(s3, args.bucket):
            console.print(f"[green]✓[/green] EventBridge enabled on {args.bucket}")
        else:
            console.print(f"[yellow]⚠️  EventBridge not enabled on {args.bucket}[/yellow]")
            console.print(f"Run: aws s3api put-bucket-notification-configuration --bucket {args.bucket} --notification-configuration '{{\"EventBridgeConfiguration\": {{}}}}'")

        # List subscriptions
        console.print(f"\n[bold]SNS Topic Subscriptions:[/bold]")
        subscriptions = eventbridge.list_topic_subscriptions(sns, topic_arn)

        table = Table(show_header=True)
        table.add_column("Protocol")
        table.add_column("Endpoint")

        for sub in subscriptions:
            if sub['Protocol'] == 'sqs':
                queue_name = sub['Endpoint'].split(':')[-1]
                table.add_row("SQS", queue_name)

        console.print(table)

        # Test file upload
        if args.test or (not args.yes and Confirm.ask("\nUpload test file to verify?")):
            test_key = f"test/eventbridge-test-{int(time.time())}.txt"
            console.print(f"\n[bold]Uploading test file...[/bold]")
            s3.put_object(
                Bucket=args.bucket,
                Key=test_key,
                Body=f"EventBridge test - {args.bucket}"
            )
            console.print(f"[green]✓[/green] Uploaded: s3://{args.bucket}/{test_key}")
            console.print(f"\nNext steps:")
            console.print(f"  1. Wait 1-2 minutes for processing")
            console.print(f"  2. Check CloudWatch Logs for rule execution")
            console.print(f"  3. Verify file appears in Quilt catalog")
            console.print(f"  4. Clean up: aws s3 rm s3://{args.bucket}/{test_key}")

        console.print(f"\n[bold green]✓ Rule setup complete![/bold green]")
        return 0

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
```

## Tool 3: `quiltx validate-infra`

### Purpose
Comprehensive infrastructure validation.

### Usage
```bash
# Validate shared infrastructure only
quiltx validate-infra --stack-name quilt-stack

# Validate specific bucket
quiltx validate-infra --stack-name quilt-stack --bucket my-bucket

# JSON output for automation
quiltx validate-infra --stack-name quilt-stack --format json

# Enable drift detection (slow)
quiltx validate-infra --stack-name quilt-stack --drift-timeout 600

# Test end-to-end search
quiltx validate-infra --stack-name quilt-stack --bucket my-bucket \
    --registry-url https://example.quiltdata.com --test-search

# Verbose logging
quiltx validate-infra --stack-name quilt-stack --verbose
```

### Functionality
Core validation checks (Phase 1 - implement these first):
1. **SNS Topic** - Verify topic exists and is accessible
2. **SQS Subscriptions** - Verify queues subscribed to SNS topic
3. **SQS Policies** - Verify queue policies allow SNS
4. **Lambda Event Sources** - Verify Lambda has SQS event source mappings
5. **Event Routing Architecture** - Verify ManifestIndexerQueue has NO direct SNS subscriptions
6. **EventBridge Rules** - Verify rules don't target ManifestIndexerQueue
7. **DLQ Health** - Check dead letter queue message counts
8. **S3 Notifications** - Verify EventBridge enabled on bucket (if bucket specified)

Extended validation checks (Phase 2 - implement later):
9. Stack drift detection
10. Lambda permissions
11. Elasticsearch indices
12. IAM policies
13. Glue partitions
14. EventBridge rules pollution
15. EsIngest queue pollution
16. IndexerQueue → SearchHandler connection
17. Recent Lambda errors
18. File search (end-to-end)
19. Package search (end-to-end)

### Implementation: `quiltx/tools/validate_infra.py`

```python
"""Infrastructure validation tool."""
from __future__ import annotations
import argparse
import sys
import json
import boto3
from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from quiltx import configured_catalog, stack, eventbridge
from quiltx.eventbridge import CheckStatus, CheckResult

console = Console()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate S3 indexing infrastructure configuration"
    )
    parser.add_argument(
        "--stack-name",
        help="CloudFormation stack name (auto-discovers if not provided)"
    )
    parser.add_argument(
        "--bucket",
        help="S3 bucket name to validate (optional)"
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--registry-url",
        help="Quilt registry URL for search testing"
    )
    parser.add_argument(
        "--test-search",
        action="store_true",
        help="Test end-to-end search functionality"
    )
    parser.add_argument(
        "--drift-timeout",
        type=int,
        default=0,
        help="Enable drift detection with timeout in seconds (default: 0 = disabled)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    return parser

def print_text_report(checks: List[CheckResult]) -> None:
    """Print validation results as formatted text."""
    table = Table(show_header=True, show_lines=True)
    table.add_column("Status", width=5)
    table.add_column("Check", style="bold")
    table.add_column("Message")

    for check in checks:
        status_style = {
            CheckStatus.PASS: "green",
            CheckStatus.FAIL: "red",
            CheckStatus.WARN: "yellow",
            CheckStatus.SKIP: "dim"
        }.get(check.status, "white")

        message = check.message
        if check.impact:
            message += f"\n[dim]Impact: {check.impact}[/dim]"
        if check.fix:
            message += f"\n[dim]Fix: {check.fix}[/dim]"

        table.add_row(
            check.status.value,
            check.name,
            message,
            style=status_style
        )

    console.print(table)

    # Summary
    passed = sum(1 for c in checks if c.status == CheckStatus.PASS)
    failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
    warnings = sum(1 for c in checks if c.status == CheckStatus.WARN)
    skipped = sum(1 for c in checks if c.status == CheckStatus.SKIP)

    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Passed: {passed}")
    console.print(f"  Failed: {failed}")
    console.print(f"  Warnings: {warnings}")
    console.print(f"  Skipped: {skipped}")

    if failed == 0:
        console.print(f"\n[bold green]✓ All checks passed![/bold green]")
    else:
        console.print(f"\n[bold red]✗ {failed} check(s) failed[/bold red]")

def print_json_report(bucket: str | None, checks: List[CheckResult]) -> None:
    """Print validation results as JSON."""
    report = {
        'bucket_name': bucket,
        'summary': {
            'passed': sum(1 for c in checks if c.status == CheckStatus.PASS),
            'failed': sum(1 for c in checks if c.status == CheckStatus.FAIL),
            'warnings': sum(1 for c in checks if c.status == CheckStatus.WARN),
            'skipped': sum(1 for c in checks if c.status == CheckStatus.SKIP),
            'is_healthy': sum(1 for c in checks if c.status == CheckStatus.FAIL) == 0,
        },
        'checks': [
            {
                'name': c.name,
                'status': c.status.name,
                'message': c.message,
                'impact': c.impact,
                'fix': c.fix
            }
            for c in checks
        ]
    }
    print(json.dumps(report, indent=2))

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        # Discover stack
        if not args.stack_name:
            catalog_url = configured_catalog()
            cfn = boto3.client('cloudformation', region_name=args.region)
            stack_info = stack.find_matching_stack(cfn, catalog_url)
            stack_name = stack_info['StackName']
        else:
            stack_name = args.stack_name

        if args.format == "text":
            console.print(f"[bold]Infrastructure Validation[/bold]")
            console.print(f"Stack: {stack_name}")
            console.print(f"Region: {args.region}")
            if args.bucket:
                console.print(f"Bucket: {args.bucket}")
            console.print()

        # Initialize AWS clients
        s3 = boto3.client('s3')
        sns = boto3.client('sns', region_name=args.region)
        sqs = boto3.client('sqs', region_name=args.region)
        lambda_client = boto3.client('lambda', region_name=args.region)
        cfn = boto3.client('cloudformation', region_name=args.region)
        events = boto3.client('events', region_name=args.region)
        sts = boto3.client('sts')

        # Discover resources
        config = eventbridge.discover_stack_resources(cfn, stack_name)
        account_id = sts.get_caller_identity()['Account']

        # Get bucket region and SNS topic
        bucket_region = args.region
        topic_arn = None
        if args.bucket:
            bucket_region = eventbridge.get_bucket_region(s3, args.bucket)
            # Construct topic ARN (or discover from bucket)
            topic_arn = f"arn:aws:sns:{bucket_region}:{account_id}:quilt-eventbridge-notifications"

        # Run validation checks
        checks: List[CheckResult] = []

        # Core checks (Phase 1)
        if topic_arn:
            checks.append(eventbridge.validate_sns_topic(sns, topic_arn))
            checks.append(eventbridge.validate_sqs_subscriptions(sns, topic_arn, config))
            checks.append(eventbridge.validate_sqs_policies(
                sqs,
                [config.get('indexer_queue_url'), config.get('pkg_events_queue_url')],
                topic_arn,
                bucket_region,
                args.region
            ))

        if config.get('indexer_lambda_arn') and config.get('indexer_queue_url'):
            queue_arn = eventbridge.queue_url_to_arn(
                config['indexer_queue_url'], args.region, account_id
            )
            checks.append(eventbridge.validate_lambda_event_source(
                lambda_client, config['indexer_lambda_arn'], queue_arn
            ))

        checks.append(eventbridge.validate_event_routing_architecture(sns, sqs, config))
        checks.append(eventbridge.validate_eventbridge_rules(events, config))

        dlq_urls = [
            url for url in [
                config.get('indexer_dlq_url'),
                config.get('pkg_events_dlq_url'),
                config.get('eventbridge_dlq_url')
            ] if url
        ]
        if dlq_urls:
            checks.append(eventbridge.validate_dlq_health(sqs, dlq_urls))

        if args.bucket:
            checks.append(eventbridge.validate_s3_notifications(s3, args.bucket))

        # Extended checks (Phase 2 - optional)
        if args.drift_timeout > 0:
            checks.append(eventbridge.validate_stack_drift(cfn, stack_name, args.drift_timeout))

        # Output results
        if args.format == "json":
            print_json_report(args.bucket, checks)
        else:
            print_text_report(checks)

        # Return exit code
        failed = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        return 0 if failed == 0 else 1

    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"[bold red]Error:[/bold red] {e}", style="red")
            if args.verbose:
                import traceback
                traceback.print_exc()
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
```

### Output Format

**Text format** (default):
- Rich table with color-coded status
- Detailed messages with impact and fix suggestions
- Summary statistics
- Clear pass/fail indication

**JSON format** (for automation):
```json
{
  "bucket_name": "my-bucket",
  "summary": {
    "passed": 6,
    "failed": 1,
    "warnings": 2,
    "skipped": 0,
    "is_healthy": false
  },
  "checks": [
    {
      "name": "SNS Topic",
      "status": "PASS",
      "message": "Topic exists: arn:aws:sns:us-east-1:123456789012:quilt-eventbridge-notifications",
      "impact": null,
      "fix": null
    },
    {
      "name": "Event Routing Architecture",
      "status": "FAIL",
      "message": "ManifestIndexerQueue has direct SNS subscription",
      "impact": "Events will be processed twice, causing duplicates",
      "fix": "Unsubscribe ManifestIndexerQueue from SNS topic"
    }
  ]
}
```

### Exit Codes
- `0` - All checks passed
- `1` - One or more checks failed
- `2` - Script error (invalid arguments, connection error, etc.)

## Tool 4: `quiltx eventbridge-status`

### Purpose
Quick status check for EventBridge setup.

### Usage
```bash
# Check status for bucket
quiltx eventbridge-status --bucket my-bucket

# Explicit stack
quiltx eventbridge-status --bucket my-bucket --stack-name quilt-stack
```

### Functionality
Simplified validation (subset of full validation):
1. EventBridge enabled on bucket
2. SNS topic exists
3. Subscribed queues
4. Recent EventBridge rule invocations (CloudWatch metrics)
5. Recent errors in Lambda logs

### Implementation: `quiltx/tools/eventbridge_status.py`

```python
"""EventBridge status tool."""
from __future__ import annotations
import argparse
import sys
import boto3
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from quiltx import eventbridge

console = Console()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check EventBridge status for S3 bucket"
    )
    parser.add_argument(
        "--bucket",
        required=True,
        help="S3 bucket name"
    )
    parser.add_argument(
        "--stack-name",
        help="CloudFormation stack name"
    )
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        # Get bucket region
        s3 = boto3.client('s3')
        bucket_region = eventbridge.get_bucket_region(s3, args.bucket)

        console.print(f"[bold]EventBridge Status: {args.bucket}[/bold]")
        console.print(f"Region: {bucket_region}\n")

        # Check EventBridge configuration
        enabled = eventbridge.check_eventbridge_enabled(s3, args.bucket)
        status = "[green]✓ Enabled[/green]" if enabled else "[red]✗ Disabled[/red]"
        console.print(f"EventBridge: {status}")

        # Get SNS topic subscriptions
        sns = boto3.client('sns', region_name=bucket_region)
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        topic_arn = f"arn:aws:sns:{bucket_region}:{account_id}:quilt-eventbridge-notifications"

        console.print(f"\n[bold]Subscriptions:[/bold]")
        subscriptions = eventbridge.list_topic_subscriptions(sns, topic_arn)

        table = Table(show_header=True)
        table.add_column("Queue")
        table.add_column("Status")

        for sub in subscriptions:
            if sub['Protocol'] == 'sqs':
                queue_name = sub['Endpoint'].split(':')[-1]
                table.add_row(queue_name, "[green]✓[/green]")

        console.print(table)

        # Check CloudWatch metrics for recent invocations
        console.print(f"\n[bold]Recent Activity (last 24h):[/bold]")
        cw = boto3.client('cloudwatch', region_name=bucket_region)

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        # Get EventBridge rule invocations
        response = cw.get_metric_statistics(
            Namespace='AWS/Events',
            MetricName='Invocations',
            Dimensions=[
                {'Name': 'RuleName', 'Value': 'quilt-s3-events-rule'}
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Sum']
        )

        total_invocations = sum(dp['Sum'] for dp in response.get('Datapoints', []))
        console.print(f"EventBridge invocations: {int(total_invocations)}")

        return 0

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
```

## Testing Strategy

### Unit Tests

#### `tests/test_eventbridge.py`
Test library functions with boto3 Stubber:
```python
from botocore.stub import Stubber
import boto3
from quiltx import eventbridge

def test_create_input_transformer():
    transformer = eventbridge.create_input_transformer()
    assert 'InputPathsMap' in transformer
    assert 'InputTemplate' in transformer
    assert 'awsRegion' in transformer['InputPathsMap']

def test_queue_url_to_arn():
    arn = eventbridge.queue_url_to_arn(
        'https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue',
        'us-east-1',
        '123456789012'
    )
    assert arn == 'arn:aws:sqs:us-east-1:123456789012:MyQueue'

def test_create_sns_topic():
    client = boto3.client('sns', region_name='us-east-1')
    stubber = Stubber(client)

    stubber.add_response(
        'create_topic',
        {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test-topic'},
        {'Name': 'test-topic'}
    )

    with stubber:
        arn = eventbridge.create_sns_topic(client, 'test-topic', 'us-east-1')
        assert arn == 'arn:aws:sns:us-east-1:123456789012:test-topic'

def test_validate_sns_topic_pass():
    client = boto3.client('sns', region_name='us-east-1')
    stubber = Stubber(client)

    stubber.add_response(
        'get_topic_attributes',
        {'Attributes': {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test'}},
        {'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test'}
    )

    with stubber:
        result = eventbridge.validate_sns_topic(client, 'arn:aws:sns:us-east-1:123456789012:test')
        assert result.status == eventbridge.CheckStatus.PASS

def test_validate_sns_topic_fail():
    client = boto3.client('sns', region_name='us-east-1')
    stubber = Stubber(client)

    stubber.add_client_error('get_topic_attributes', 'NotFound')

    with stubber:
        result = eventbridge.validate_sns_topic(client, 'arn:aws:sns:us-east-1:123456789012:missing')
        assert result.status == eventbridge.CheckStatus.FAIL
```

#### `tests/test_eventbridge_setup.py`
Test setup tool:
```python
from quiltx.tools import eventbridge_setup

def test_main_basic(monkeypatch):
    # Mock all AWS calls
    # Test basic setup flow
    pass

def test_cross_region_policy_generation():
    # Test cross-region policy generation
    pass
```

#### `tests/test_eventbridge_rule.py`
Test rule tool:
```python
from quiltx.tools import eventbridge_rule

def test_determine_buckets_add():
    # Test adding bucket to existing rule
    pass

def test_determine_buckets_replace():
    # Test replacing bucket in rule
    pass
```

#### `tests/test_validate_infra.py`
Test validation tool:
```python
from quiltx.tools import validate_infra

def test_validation_all_pass():
    # Mock all checks passing
    pass

def test_validation_with_failures():
    # Mock some checks failing
    pass

def test_json_output():
    # Test JSON format output
    pass
```

### Integration Tests

#### `tests/test_eventbridge_integration.py`
```python
import pytest
import os

@pytest.mark.integration
@pytest.mark.skipif(
    not os.getenv('QUILTX_EVENTBRIDGE_INTEGRATION'),
    reason="Set QUILTX_EVENTBRIDGE_INTEGRATION=1 to run"
)
def test_setup_real_bucket():
    # Test against real AWS resources
    pass

@pytest.mark.integration
def test_validation_real_stack():
    # Test validation against real stack
    pass
```

## Dependencies

All required dependencies are already in `pyproject.toml`:
- `boto3` - AWS SDK
- `rich` - Terminal formatting
- `quilt3` - Catalog integration (optional, for search tests)
- `platformdirs` - Config storage

No new dependencies required.

## Documentation Updates

### README.md
Add new section:

````markdown
## EventBridge Tools

### Setup EventBridge for a bucket
```bash
quiltx eventbridge-setup --bucket my-bucket
```

### Create EventBridge rule
```bash
quiltx eventbridge-rule my-bucket
```

### Validate infrastructure
```bash
quiltx validate-infra --stack-name my-stack --bucket my-bucket
```

### Check EventBridge status
```bash
quiltx eventbridge-status --bucket my-bucket
```
````

### CLAUDE.md
Add examples:

```markdown
### EventBridge Configuration

- Setup: `./poe run eventbridge-setup --bucket my-bucket`
- Validate: `./poe run validate-infra --stack-name my-stack --bucket my-bucket --format json`
```

## Implementation Phases

### Phase 1: Core Library + Setup Tools (Week 1)
- Implement `quiltx/eventbridge.py` (core functions)
- Implement `quiltx/tools/eventbridge_setup.py`
- Implement `quiltx/tools/eventbridge_rule.py`
- Unit tests for library and tools
- Manual testing with real AWS resources

### Phase 2: Validation Tool - Core Checks (Week 2)
- Implement `quiltx/tools/validate_infra.py` with core checks:
  - SNS topic validation
  - SQS subscriptions
  - SQS policies
  - Lambda event sources
  - Event routing architecture
  - EventBridge rules
  - DLQ health
  - S3 notifications
- Unit tests for validation checks
- JSON output format
- Manual testing

### Phase 3: Validation Tool - Extended Checks (Week 3)
- Add extended validation checks:
  - Stack drift detection
  - Lambda permissions
  - Elasticsearch indices
  - IAM policies
  - Glue partitions
  - EventBridge rules pollution
  - Recent Lambda errors
  - End-to-end search testing
- Integration tests
- Documentation

### Phase 4: Status Tool + Polish (Week 4)
- Implement `quiltx/tools/eventbridge_status.py`
- CloudWatch metrics integration
- Comprehensive integration tests
- Documentation updates
- Release preparation

## Success Criteria

1. ✅ All tools auto-discovered by `quiltx --help`
2. ✅ Each tool has comprehensive `--help` documentation
3. ✅ Unit tests pass: `./poe test`
4. ✅ Integration tests pass: `QUILTX_EVENTBRIDGE_INTEGRATION=1 ./poe test`
5. ✅ Validate-infra returns correct exit codes (0/1/2)
6. ✅ JSON output is valid and parseable
7. ✅ Cross-region setup works correctly
8. ✅ Rich formatting displays correctly in terminal
9. ✅ Manual testing against real AWS resources succeeds
10. ✅ Documentation is clear and comprehensive

## Future Enhancements (Out of Scope)

1. Auto-remediation of common misconfigurations
2. Continuous monitoring/watch mode
3. Alert integration
4. Web dashboard
5. Terraform/CDK export
6. Multi-catalog support
7. Historical trending
