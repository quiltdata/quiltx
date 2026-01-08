# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-08

### Added
- Unified CLI with single `quiltx` entry point
- Built-in tools: `log` and `stack`
- Simple tool registry system for adding new tools
- Shared utilities library with `configured_catalog` helper

### Changed
- **BREAKING**: Restructured from multiple separate packages to single unified package
- **BREAKING**: Removed `quiltx-log` and `quiltx-stack` as separate packages
- **BREAKING**: Changed command interface from `uvx quiltx run <tool>` to `uvx quiltx <tool>`
- Flattened directory structure (removed nested `quiltx/quiltx/` directory)
- Updated workflows to build single package instead of matrix of packages

### Removed
- Separate `tools/quiltx-log/` and `tools/quiltx-stack/` packages
- Old CLI commands: `quiltx list`, `quiltx install`, `quiltx run`

## [Pre-0.1.0] - Previous Structure

Previous version consisted of:
- `quiltx`: Shared library package
- `quiltx-log`: Standalone logging tool
- `quiltx-stack`: Standalone stack trace tool
- CLI wrapper for managing separate tool installations
