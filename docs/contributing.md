# Contributing to quiltx

Thank you for your interest in contributing to quiltx! This guide will help you set up your development environment and understand our development workflow.

## Development Setup

### Prerequisites

- Python 3.9 or higher
- [uv](https://github.com/astral-sh/uv) package manager

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/quiltdata/quiltx.git
cd quiltx

# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install development dependencies and pre-commit hooks
./poe setup
```

The `./poe setup` command will:
- Install all development dependencies
- Set up pre-commit hooks for code quality
- Set up pre-push hooks for testing

## Development Workflow

### Running quiltx from Source

Use the `poe run` command to run quiltx from the repository:

```bash
# List available tools
./poe run --list

# Run a specific tool
./poe run config
./poe run stack
./poe run logs --minutes 30

# Get help
./poe run --help
./poe run <tool> --help
```

### Running Tests

```bash
# Run unit tests only
./poe test

# Run full test suite (setup, lint, and all tests)
./poe test-all

# Run tests directly with pytest
pytest tests

# Run with coverage
pytest --cov=quiltx tests
```

### Code Quality

```bash
# Format code and run type checking
./poe lint

# Check formatting without modifying (for CI)
./poe lint-check

# Run pre-commit hooks manually
pre-commit run --all-files
```

### Code Style

We use:
- **black** for code formatting (line length: 88)
- **mypy** for static type checking
- Pre-commit hooks to enforce quality standards

All code should:
- Pass black formatting
- Pass mypy type checking
- Include type hints for function signatures
- Have docstrings for public functions

## Project Structure

```text
quiltx/
├── quiltx/                 # Main package
│   ├── __init__.py        # Package exports (configured_catalog, __version__)
│   ├── _version.py        # Version string
│   ├── cli.py             # Unified CLI with auto-discovery
│   ├── config.py          # Catalog configuration
│   ├── stack.py           # CloudFormation stack discovery API
│   ├── logs.py            # CloudWatch logs utilities
│   ├── utils.py           # Shared utilities
│   └── tools/             # CLI tools (auto-discovered)
│       ├── config.py      # Configure catalogs
│       ├── stack.py       # Discover stacks
│       ├── logs.py        # View logs
│       └── ecs.py         # ECS shell access
├── tests/                 # Test suite
│   ├── test_stack.py      # Stack API tests
│   ├── test_config.py     # Config tests
│   └── ...
├── spec/                  # Specification documentation
├── docs/                  # MkDocs documentation
├── pyproject.toml         # Package configuration
├── poe                    # Task runner wrapper script
└── CHANGELOG.md           # Release history
```

## Adding New Tools

Tools in `quiltx/tools/` are automatically discovered by the CLI. To add a new tool:

### 1. Create Tool File

Create a new file in `quiltx/tools/` (e.g., `mytool.py`):

```python
"""Description of my tool."""
import argparse
import sys

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="My tool does something useful"
    )
    parser.add_argument("--option", help="An option")
    return parser

def main(argv: list[str] | None = None) -> int:
    """Main entry point for the tool.

    Args:
        argv: Command-line arguments (uses sys.argv if None)

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        # Tool implementation
        print(f"Running with option: {args.option}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
```

### 2. Use quiltx APIs

Leverage existing quiltx utilities:

```python
from quiltx import configured_catalog
from quiltx.stack import load_stack_payload, ensure_min_version

def main(argv: list[str] | None = None) -> int:
    # Get configured catalog
    catalog_url = configured_catalog()
    if not catalog_url:
        print("No catalog configured. Run 'quiltx config'.", file=sys.stderr)
        return 1

    # Load cached stack data
    from urllib.parse import urlparse
    catalog_name = urlparse(catalog_url).netloc
    payload = load_stack_payload(catalog_name)

    if not payload:
        print("Run 'quiltx stack' first.", file=sys.stderr)
        return 1

    # Check version compatibility if needed
    if not ensure_min_version(payload, "0.1.3"):
        print("Please run 'quiltx stack' to refresh.", file=sys.stderr)
        return 1

    # Use the data...
    return 0
```

### 3. Add Tests

Create tests in `tests/test_mytool.py`:

```python
"""Tests for mytool."""
import pytest
from quiltx.tools import mytool

def test_mytool_basic():
    """Test basic functionality."""
    result = mytool.main(["--option", "value"])
    assert result == 0

def test_mytool_error_handling():
    """Test error cases."""
    result = mytool.main(["--invalid"])
    assert result != 0
```

### 4. Test Your Tool

```bash
# Run from source
./poe run mytool --help

# Run tests
pytest tests/test_mytool.py

# Run all tests
./poe test
```

### 5. Document Your Tool

Add documentation to:
- Docstrings in the tool file
- User guide: `docs/user-guide/cli-tools.md`
- API reference (mkdocstrings will auto-generate from docstrings)

## Testing

### Test Categories

We have several test markers:

```python
@pytest.mark.integration
def test_requires_live_services():
    """This test requires AWS credentials and live services."""
    pass
```

### Integration Tests

Integration tests are skipped by default. To run them:

```bash
# Enable integration tests
QUILTX_STACK_INTEGRATION=1 pytest tests

# Or use the poe task
./poe test-all
```

Integration tests require:
- AWS credentials configured
- Access to live CloudFormation stacks
- CloudWatch Logs permissions

### Writing Tests

Best practices:
- Test both success and error cases
- Mock AWS calls for unit tests
- Use fixtures for common setup
- Test command-line argument parsing
- Verify exit codes

Example:

```python
import pytest
from unittest.mock import patch

def test_tool_with_mock():
    """Test tool with mocked AWS calls."""
    with patch('boto3.client') as mock_client:
        mock_client.return_value.describe_stacks.return_value = {
            'Stacks': [{'StackName': 'TestStack'}]
        }

        result = my_tool.main(['--stack', 'TestStack'])
        assert result == 0
```

## Version Bumping

We use semantic versioning (MAJOR.MINOR.PATCH).

```bash
# Bump patch version (0.2.0 -> 0.2.1)
./poe bump

# Bump minor version (0.2.0 -> 0.3.0)
./poe bump minor

# Bump major version (0.2.0 -> 1.0.0)
./poe bump major
```

This updates the version in `pyproject.toml`.

## Publishing a Release

See [Publishing Process](https://github.com/quiltdata/quiltx/blob/main/CLAUDE.md#publish-to-pypi) for detailed release instructions.

Quick summary:

1. Update version: `./poe bump [major|minor|patch]`
2. Update `CHANGELOG.md` with release notes
3. Commit changes
4. Create and push tag: `./poe tag`
5. GitHub Actions will automatically:
   - Create a GitHub Release
   - Publish to PyPI (after approval)

## Documentation

### Building Documentation Locally

```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Serve documentation locally
mkdocs serve

# View at http://127.0.0.1:8000
```

### Documentation Structure

- `docs/index.md` - Homepage
- `docs/getting-started.md` - Installation and setup
- `docs/user-guide/` - User guides for tools and APIs
- `docs/api/` - Auto-generated API reference
- `docs/changelog.md` - Release history
- `docs/contributing.md` - This file

### Writing Documentation

- Use Markdown for all documentation
- Include code examples
- Add type hints (shown in API reference)
- Use Google-style docstrings:

```python
def my_function(arg1: str, arg2: int) -> bool:
    """Short description.

    Longer description with more details.

    Args:
        arg1: Description of arg1
        arg2: Description of arg2

    Returns:
        Description of return value

    Raises:
        ValueError: When arg2 is negative

    Example:
        >>> my_function("test", 42)
        True
    """
    pass
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `./poe test`
5. Run linting: `./poe lint`
6. Commit changes (pre-commit hooks will run automatically)
7. Push to your fork: `git push origin feature/my-feature`
8. Open a pull request

### PR Guidelines

- Write clear commit messages
- Include tests for new features
- Update documentation as needed
- Ensure CI passes
- Keep PRs focused on a single feature/fix

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/quiltdata/quiltx/issues)
- **Discussions**: [GitHub Discussions](https://github.com/quiltdata/quiltx/discussions)
- **Documentation**: [quiltx.readthedocs.io](https://quiltx.readthedocs.io)

## Code of Conduct

Be respectful and constructive in all interactions. We aim to foster an inclusive and welcoming community.

## License

By contributing to quiltx, you agree that your contributions will be licensed under the MIT License.
