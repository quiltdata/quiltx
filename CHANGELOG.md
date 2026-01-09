# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-01-08

### Added

- Stack discovery tool and supporting library for CloudFormation metadata caching
- Logs tool and helper library for CloudWatch log retrieval with time filters
- Linting workflow with Black and mypy, plus pre-commit hooks and CI validation

## [0.1.0] - 2026-01-08

Initial release of quiltx - a unified toolkit for Quilt workflows.

### Added

- Unified CLI with single `quiltx` entry point
- Built-in tool: `config` for configuring Quilt catalogs using `configured_catalog` API
- Automatic tool discovery system (no explicit registry needed)
- Shared utilities library with `configured_catalog` helper
- Comprehensive tests for CLI and config tool
