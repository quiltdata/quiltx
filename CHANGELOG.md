<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-01-09

### Changed

- **Publishing workflow improvements**:
  - Automated PyPI publishing now triggers directly on git tag pushes (no manual GitHub Release creation needed)
  - GitHub Releases are automatically created with release notes when tags are pushed
  - Build system switched from pip to uv for faster, more reliable builds
  - Distribution files (wheel and tarball) automatically attached to GitHub Releases

## [0.1.2] - 2026-01-08

### Added

- `logs` tool: Enhanced log display and filtering capabilities
  - Stream-based filtering: Filter logs by stream name with substring matching (e.g., `quiltx logs registry/registry`)
  - `--wrap` flag: Option to wrap long log messages instead of truncating (auto-enabled when filtering by stream)
  - Health check coalescing: Consecutive health check log entries are automatically summarized to reduce noise
  - Default behavior now shows all log streams instead of just LogGroup
- Developer tooling improvements:
  - Enhanced `bump_version.py` script with automated git commit workflow
  - Version bumping now automatically updates `uv.lock` and commits all changes
  - Added git status validation to prevent bumping with uncommitted changes

### Changed

- `logs` tool positional arguments now filter by stream name instead of log group keys
- Health check detection improved to recognize ELB health checker and GET / requests

## [0.1.1] - 2026-01-08

### Added

- `stack` tool: Discover and cache CloudFormation stack metadata with catalog matching
  - `--catalog-name` flag for flexible catalog specification without quilt3 config
  - Summary display showing stack name, region, account, and resource counts
- `logs` tool: Retrieve and follow CloudWatch logs with dynamic display
  - Follow mode enabled by default with single-screen dynamic updates using Rich Live
  - Time-based filtering (--since, --until)
  - Color-coded log levels (ERROR=red, WARN=yellow, INFO=blue, DEBUG=dim)
  - Auto-detecting console size and stream management
- CLI improvements: Subparsers showing all available tools with descriptions
- Developer tooling enhancements:
  - Pre-commit hooks with Black and mypy
  - CI lint validation workflow
  - Poe task sequences for automated dependency management (`./poe setup`, `./poe sync`)
  - Simplified developer documentation in AGENTS.md

## [0.1.0] - 2026-01-08

Initial release of quiltx - a unified toolkit for Quilt workflows.

### Added

- Unified CLI with single `quiltx` entry point
- Built-in tool: `config` for configuring Quilt catalogs using `configured_catalog` API
- Automatic tool discovery system (no explicit registry needed)
- Shared utilities library with `configured_catalog` helper
- Comprehensive tests for CLI and config tool
