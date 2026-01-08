# quiltx

A unified toolkit for Quilt workflows with built-in tools and shared utilities.

## Installation

```bash
# No installation needed! Use uvx to run directly:
uvx quiltx --list

# Or install globally with pipx:
pipx install quiltx
```

## Usage

Run tools directly with `uvx` (recommended):

```bash
# List available tools
uvx quiltx --list

# Run the log tool
uvx quiltx log "your message" --level info

# Run the stack tool
uvx quiltx stack --limit 5

# Get help
uvx quiltx --help
uvx quiltx <tool> --help
```

Or if installed with `pipx`:

```bash
quiltx --list
quiltx log "your message"
```

## Built-in Tools

- **log**: Emit structured JSON log lines
- **stack**: Print stack trace summaries

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
│  ├─ cli.py           # Unified CLI entry point
│  ├─ tools/           # Built-in tools
│  │  ├─ log.py
│  │  └─ stack.py
│  └─ __init__.py      # Shared utilities
├─ tests/              # Test suite
├─ pyproject.toml      # Package configuration
└─ poe                 # Task runner script
```

### Adding New Tools

To add a new tool:

1. Create a new file in `quiltx/tools/` (e.g., `mytool.py`)
1. Implement a `main(argv)` function that returns an exit code
1. Register it in `quiltx/cli.py` in the `TOOLS` dictionary:

```python
TOOLS = {
    "stack": "quiltx.tools.stack",
    "log": "quiltx.tools.log",
    "mytool": "quiltx.tools.mytool",  # Add your tool here
}
```

1. Add tests in `tests/`

## License

MIT License - see LICENSE file for details
