# CLI Tools Reference

quiltx provides a unified command-line interface with auto-discovered tools. All tools are available via `quiltx <tool>` after installation.

## General Usage

```bash
# List all available tools
quiltx --list

# Get help for any tool
quiltx <tool> --help

# General help
quiltx --help
```

## Built-in Tools

### config

Configure and display Quilt catalog settings.

**Usage:**

```bash
# Configure with a catalog URL
quiltx config --catalog https://example.quiltdata.com

# Show current configuration
quiltx config

# Interactive configuration
quiltx config
```

**Options:**

- `--catalog URL` - Set the catalog URL to configure

**Details:**

The `config` tool stores your Quilt catalog configuration in `~/.config/quilt/` for use by other tools. It uses the `configured_catalog()` API internally.

---

### stack

Discover and cache CloudFormation stack metadata for your Quilt deployment.

**Usage:**

```bash
# Discover stack and cache metadata
quiltx stack

# Force refresh cached data
quiltx stack --refresh
```

**What it does:**

1. Discovers the CloudFormation stack associated with your configured catalog
2. Retrieves stack metadata including:
   - Stack name and region
   - Log group resources
   - ECS service resources
   - EventBridge resources
3. Caches the data in `~/.local/share/quiltx/{catalog_name}/stack.json`

**Output:**

The tool displays:
- Stack name and region
- Available CloudWatch log groups
- ECS clusters and services
- Other relevant resources

**Cached Data:**

The cached `stack.json` file includes:
- `catalog_name` - Configured catalog name
- `quiltx_version` - Version of quiltx that created the cache
- `region` - AWS region
- `stack_name` - CloudFormation stack name
- `log_groups` - List of CloudWatch log groups
- `ecs_resources` - ECS cluster and service information
- `eventbridge_resources` - EventBridge rules and targets

**Why cache?**

Other tools like `logs` and `ecs` use this cached data to avoid repeated AWS API calls, making operations faster and more reliable.

---

### logs

Retrieve and display CloudWatch logs from your Quilt deployment.

**Usage:**

```bash
# Show recent logs (default: last 10 minutes)
quiltx logs

# Show logs from the last 30 minutes
quiltx logs --minutes 30

# Filter logs by pattern
quiltx logs --filter "ERROR"

# Follow logs in real-time
quiltx logs --follow

# Show logs from specific log group
quiltx logs --log-group /aws/ecs/my-service

# Combine options
quiltx logs --minutes 60 --filter "POST /api" --follow
```

**Options:**

- `--minutes N` - Show logs from the last N minutes (default: 10)
- `--filter PATTERN` - Filter logs matching pattern (case-insensitive)
- `--follow` - Follow logs in real-time (like `tail -f`)
- `--log-group NAME` - Show logs from specific log group

**Prerequisites:**

- Run `quiltx stack` first to cache stack metadata
- AWS credentials with CloudWatch Logs permissions

**Details:**

The `logs` tool uses the cached `stack.json` to find available log groups and retrieves logs using the CloudWatch Logs API. It automatically formats timestamps and handles pagination for large log volumes.

---

### ecs

Open an interactive shell in running ECS tasks for debugging.

**Usage:**

```bash
# List available ECS clusters and services
quiltx ecs --list

# Open shell in a specific service
quiltx ecs RegistryService

# Check network connectivity from ECS to catalog services
quiltx ecs --reachability
```

**Options:**

- `--list` - List all available ECS clusters and services
- `--reachability` - Test network connectivity to catalog endpoints
- `SERVICE_NAME` - Open interactive shell in the specified service

**Prerequisites:**

1. **AWS Session Manager Plugin** - Required for executing commands in ECS tasks
   - If not installed, `quiltx ecs` will display platform-specific installation instructions
   - See [AWS documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)

2. **ECS Task Configuration** - Tasks must have:
   - `enableExecuteCommand` enabled
   - Appropriate IAM permissions for ECS Exec

3. **AWS Permissions** - You need:
   - `ecs:ExecuteCommand`
   - `ecs:DescribeTasks`
   - `ssm:StartSession`

**Installation Instructions:**

The plugin installation varies by platform:

=== "macOS"
    ```bash
    brew install --cask session-manager-plugin
    ```

=== "Linux"
    ```bash
    curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
    sudo dpkg -i session-manager-plugin.deb
    ```

=== "Windows"
    Download and run the installer from:
    https://s3.amazonaws.com/session-manager-downloads/plugin/latest/windows/SessionManagerPluginSetup.exe

**Interactive Shell:**

Once connected, you'll have a bash shell inside the ECS task where you can:
- Inspect running processes
- Check environment variables
- Test network connectivity
- Debug application issues
- View container filesystem

**Reachability Check:**

The `--reachability` option tests connectivity from ECS tasks to:
- Catalog API endpoints
- S3 buckets
- Database connections
- Other dependent services

This is useful for diagnosing network configuration issues.

---

## Adding Custom Tools

quiltx supports adding your own custom tools. Tools are automatically discovered from the `quiltx/tools/` directory.

**To add a new tool:**

1. Create a new Python file in `quiltx/tools/` (e.g., `mytool.py`)
2. Implement a `main(argv)` function that returns an exit code
3. The tool becomes available as `quiltx mytool`

**Example tool structure:**

```python
"""My custom tool."""
import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="My tool description")
    parser.add_argument("--option", help="An option")
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Tool implementation
    print(f"Running with option: {args.option}")

    return 0
```

**Best practices:**

- Use argparse for command-line parsing
- Return 0 for success, non-zero for errors
- Add tests in `tests/`
- Include a docstring describing the tool
- Use the `configured_catalog()` API to access catalog configuration
- Use `load_stack_payload()` to access cached stack data

## Common Workflows

### Initial Setup

```bash
# 1. Configure your catalog
quiltx config --catalog https://example.quiltdata.com

# 2. Discover and cache stack information
quiltx stack

# 3. View recent logs
quiltx logs
```

### Debugging Issues

```bash
# Check recent errors
quiltx logs --filter "ERROR" --minutes 60

# Follow logs in real-time
quiltx logs --follow

# Open shell in ECS for deeper inspection
quiltx ecs RegistryService
```

### Regular Monitoring

```bash
# Check logs periodically
quiltx logs --minutes 15

# Test connectivity
quiltx ecs --reachability
```

## Troubleshooting

### "Stack data not found"

Run `quiltx stack` first to cache stack metadata:

```bash
quiltx stack
```

### "No catalog configured"

Configure a catalog with:

```bash
quiltx config --catalog https://your-catalog.quiltdata.com
```

### "Permission denied" errors

Ensure your AWS credentials have the necessary permissions:
- CloudFormation read permissions
- CloudWatch Logs read permissions
- ECS execute command permissions (for `ecs` tool)

### Session Manager Plugin issues

If `quiltx ecs` can't find the Session Manager plugin:

1. Run `quiltx ecs` to see installation instructions
2. Follow the platform-specific installation steps
3. Verify installation: `session-manager-plugin --version`
