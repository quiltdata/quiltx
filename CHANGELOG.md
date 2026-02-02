<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-01

### Added

- **Documentation and Read the Docs integration**:
  - MkDocs documentation site with Material theme
  - Read the Docs configuration for automated docs building
  - Comprehensive API reference documentation with mkdocstrings
  - User guides for CLI tools and Stack API
  - Getting started guide and contributing documentation
  - Dark mode support and enhanced navigation
- **New semantic configuration functions**:
  - `get_catalog_config()`: Get the full quilt3 catalog configuration
  - `get_catalog_url()`: Get the catalog URL from configuration
  - `get_catalog_region()`: Get the AWS region from configuration
  - `set_catalog_url()`: Set the catalog URL in quilt3 configuration

### Changed

- **BREAKING**: Removed `configured_catalog()` function
  - Replace `configured_catalog()` with `get_catalog_config()` for full config
  - Replace `configured_catalog()["navigator_url"]` with `get_catalog_url()`
  - Use `set_catalog_url()` to configure a new catalog instead of `configured_catalog(url)`
- All new functions have clear, semantic names that indicate whether they read or write
- New functions raise `ValueError` with helpful messages when catalog is not configured
- **Documentation improvements**:
  - README simplified with focus on installation and quick examples
  - AGENTS.md streamlined for developer reference
  - API reference updated to use new config function names
  - Contributing guide updated with new API exports

### Fixed

- Documentation now properly references the new config API instead of deprecated `configured_catalog()`

## [0.2.1] - 2026-02-01

### Added

- Version bump to 0.2.1 for intermediate release

## [0.2.0] - 2026-02-01

### Added

- **New `ecs` tool**: Interactive shell access to ECS tasks
  - Open interactive shells in running ECS containers using AWS Session Manager
  - Automatic Session Manager plugin detection with installation instructions
  - Smart defaults: Auto-selects RegistryService and remembers previous selections
  - Reachability checks: Test network connectivity to catalog services from ECS (`--reachability`)
  - Execute Command management: Automatically detects and enables Execute Command on services
  - Interactive prompts for cluster/service selection with `--prompt` flag
  - List mode: View available ECS clusters and services with `--list`
  - Region auto-detection from stack payload
- **New `utils` module**: General utility functions
  - `get_bucket_region()`: Get AWS region of S3 buckets
  - `normalize_url()`: Normalize URLs to canonical form
  - `get_hostname()`: Extract hostname from URLs
- **Stack payload enhancements**:
  - ECS resources now included in stack payload (`ecs_resources`)
  - Catalog configuration cached in stack payload (`catalog_config`)
  - Version tracking with `quiltx_version` field
  - New `load_stack_payload()` function for loading cached data
  - New `ensure_min_version()` function for version compatibility checks
- **Stack API improvements**:
  - New `list_ecs_resources()` function for discovering ECS clusters/services
  - Auto-detection of AWS region from catalog configuration
  - Automatic boto3 client creation when not provided

### Changed

- **Stack API simplified**: CloudFormation client now optional
  - `find_matching_stack()`: Now accepts `region` parameter and creates client automatically
  - `list_log_group_resources()`: Now accepts `region` parameter and creates client automatically
  - All stack functions can optionally accept pre-configured boto3 clients for advanced use cases
- **Code organization**:
  - Moved `configured_catalog()` to separate `quiltx.config` module
  - Created `quiltx._version` module for centralized version management
  - Reduced exports from `quiltx.__init__` to only `__version__` and `configured_catalog`
- **Developer tooling**:
  - Updated `bump_version.py` script to use `_version.py` instead of `__init__.py`

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
