# Getting Started

This guide will help you install quiltx and get started with your first commands.

## Installation

### Quick Start with uvx (Recommended)

No installation needed! Use `uvx` to run quiltx directly without installing it:

```bash
# List available tools
uvx quiltx --list

# Run any command
uvx quiltx config https://open.quiltdata.com
```

### Install with pip

For persistent installation:

```bash
pip install quiltx
```

### Install with pipx

For isolated installation in its own virtual environment:

```bash
pipx install quiltx
```

## Prerequisites

### AWS Credentials

Most quiltx tools require AWS credentials to access CloudFormation stacks, CloudWatch logs, and ECS services. Ensure your AWS credentials are configured:

```bash
# Option 1: AWS CLI configuration
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Option 3: AWS profiles
export AWS_PROFILE="your-profile-name"
```

### AWS Permissions

You'll need IAM permissions for:

- **CloudFormation**: `cloudformation:DescribeStacks`, `cloudformation:ListStackResources`
- **CloudWatch Logs**: `logs:DescribeLogGroups`, `logs:GetLogEvents`, `logs:FilterLogEvents`
- **ECS**: `ecs:ListClusters`, `ecs:ListServices`, `ecs:ListTasks`, `ecs:DescribeTasks`, `ecs:ExecuteCommand`
- **SSM**: `ssm:StartSession` (for ECS shell access)

## First Steps

### 1. Configure Your Catalog

Set up your Quilt catalog URL:

```bash
# Configure with a catalog URL
quiltx config --catalog https://example.quiltdata.com

# Or interactively
quiltx config
```

This stores your catalog configuration in `~/.config/quilt/` for future use.

### 2. Discover Your Stack

Find and cache information about your Quilt deployment's CloudFormation stack:

```bash
quiltx stack
```

This command:
- Discovers the CloudFormation stack for your configured catalog
- Caches stack metadata in `~/.local/share/quiltx/{catalog_name}/stack.json`
- Lists available log groups and ECS resources

The cached stack data is used by other tools like `logs` and `ecs`.

### 3. View Logs

Retrieve CloudWatch logs from your Quilt deployment:

```bash
# Show recent logs (last 10 minutes)
quiltx logs

# Show logs from the last 30 minutes
quiltx logs --minutes 30

# Filter logs by pattern
quiltx logs --filter "ERROR"

# Follow logs in real-time
quiltx logs --follow

# Show logs from specific log group
quiltx logs --log-group /aws/ecs/my-service
```

### 4. Access ECS Shell (Optional)

Open an interactive shell in a running ECS task for debugging:

```bash
# List available services
quiltx ecs --list

# Open shell in a specific service
quiltx ecs RegistryService

# Check network connectivity
quiltx ecs --reachability
```

**Note**: The `ecs` tool requires the AWS Session Manager plugin. If not installed, the command will display installation instructions.

## Next Steps

- **[CLI Tools Reference](user-guide/cli-tools.md)**: Detailed documentation for all CLI tools
- **[Stack API Guide](user-guide/stack-api.md)**: Use quiltx programmatically in Python
- **[API Reference](api/reference.md)**: Complete Python API documentation

## Getting Help

```bash
# General help
quiltx --help

# Help for a specific tool
quiltx config --help
quiltx stack --help
quiltx logs --help
quiltx ecs --help

# List all available tools
quiltx --list
```

## Troubleshooting

### "No credentials found"

Ensure AWS credentials are configured. See [AWS Credentials](#aws-credentials) above.

### "Stack not found"

Check that:
1. Your catalog URL is correct: `quiltx config`
2. You have CloudFormation permissions
3. The catalog's CloudFormation stack exists in your configured AWS region

### "Session Manager plugin not found" (ECS tool)

Install the AWS Session Manager plugin. Run `quiltx ecs` for platform-specific installation instructions.
