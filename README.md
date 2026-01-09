# quiltx

Quilt extension toolkit with shared utilities for working with [Quilt](https://docs.quilt.bio) catalogs.

## Installation

```bash
# No installation needed! Use uvx to run directly:
uvx quiltx --list
```

## Usage

Run tools directly with `uvx` (recommended):

```bash
# List available tools
uvx quiltx --list

# Configure a Quilt catalog
uvx quiltx config https://open.quiltdata.com

# Show current catalog configuration
uvx quiltx config

# Get help
uvx quiltx --help
uvx quiltx <tool> --help
```

Or if installed with `pipx`:

```bash
quiltx --list
quiltx config https://open.quiltdata.com
quiltx stack
quiltx logs --minutes 30 --filter "ERROR"
```

## Built-in Tools

- **config**: Configure and display Quilt catalog settings using the `configured_catalog` API
- **stack**: Discover the Quilt CloudFormation stack and cache log group metadata in `stack.json`
- **logs**: Display CloudWatch Logs for the configured catalog using `stack.json`

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/ernest/quiltx.git
cd quiltx

# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Using poe (recommended)
./poe test

# Or directly with pytest
pytest tests
```

### Project Structure

```text
quiltx/
├─ quiltx/              # Main package
│  ├─ cli.py           # Unified CLI with auto-discovery
│  ├─ tools/           # Built-in tools (auto-discovered)
│  │  └─ config.py
│  └─ __init__.py      # Shared utilities (configured_catalog)
├─ tests/              # Test suite
├─ pyproject.toml      # Package configuration
└─ poe                 # Task runner script
```

### Adding New Tools

Tools are automatically discovered from the `quiltx/tools/` directory. To add a new tool:

1. Create a new file in `quiltx/tools/` (e.g., `mytool.py`)
2. Implement a `main(argv)` function that returns an exit code
3. The tool will be automatically available via `quiltx mytool`
4. Add tests in `tests/`

Example tool structure:

```python
"""My new tool."""
import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="My tool description")
    # Add arguments
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Tool implementation
    return 0
```

## License

MIT License - see LICENSE file for details
