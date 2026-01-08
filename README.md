# quiltx

A shared library plus a set of single-purpose "quiltx tools".

## Layout

```text
./
├─ quiltx/                 # the shared library
├─ tools/                  # quiltx tools (each is a package)
│  ├─ quiltx-log/
│  └─ quiltx-stack/
```

## Install uvx

`uvx` ships with `uv`. Install uv once, then verify `uvx` is on your PATH.

- Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh` or `brew install uv`
- Verify uvx: `uvx --version`

## Usage

- List installed tools: `uvx quiltx list`
- Install a tool: `uvx quiltx install quiltx-log`
- Run a tool: `uvx quiltx run quiltx-log "hello"`

## Development

- Install workspace deps: `uv sync`
- Run tools locally: `uv run quiltx-log "hello"` or `uv run quiltx-stack`
