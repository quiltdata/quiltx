# quiltx

Command-line tools for Quilt catalog administrators.

## Features

- **Configuration Management**: Configure and manage Quilt catalog connections
- **Stack Discovery**: Discover and inspect CloudFormation stacks for Quilt deployments
- **Log Access**: Retrieve and follow CloudWatch logs from ECS services and API Gateway
- **ECS Shell Access**: Open interactive shells in running ECS tasks for debugging

## Quick Start

Install quiltx from PyPI:

```bash
pip install quiltx
```

Configure your first catalog:

```bash
quiltx config --catalog https://example.quiltdata.com
```

See the [Getting Started](getting-started.md) guide for detailed installation instructions and usage examples.

## Documentation

- [Getting Started](getting-started.md) - Installation and quick start
- [User Guide](user-guide/cli-tools.md) - Detailed CLI tools reference
- [API Reference](api/reference.md) - Python API documentation
- [Changelog](changelog.md) - Release history

## Links

- [GitHub Repository](https://github.com/quiltdata/quiltx)
- [PyPI Package](https://pypi.org/project/quiltx/)
- [Issue Tracker](https://github.com/quiltdata/quiltx/issues)
