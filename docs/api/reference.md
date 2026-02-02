# API Reference

Complete Python API documentation for quiltx modules.

## Stack Module

The `quiltx.stack` module provides functions for discovering and working with CloudFormation stacks.

::: quiltx.stack
    options:
      show_root_heading: true
      show_source: true
      members:
        - find_matching_stack
        - list_log_group_resources
        - list_ecs_resources
        - load_stack_payload
        - write_stack_payload
        - ensure_min_version

## Config Module

The `quiltx.config` module provides catalog configuration utilities.

::: quiltx.config
    options:
      show_root_heading: true
      show_source: true

## CLI Module

The `quiltx.cli` module provides the unified command-line interface.

::: quiltx.cli
    options:
      show_root_heading: true
      show_source: true
      members:
        - main
        - discover_tools
        - list_tools

## Main Package

Core utilities exported from the main `quiltx` package.

::: quiltx
    options:
      show_root_heading: true
      show_source: false
      members:
        - configured_catalog
        - __version__

## Logs Module

The `quiltx.logs` module provides CloudWatch Logs utilities.

::: quiltx.logs
    options:
      show_root_heading: true
      show_source: true

## Utils Module

The `quiltx.utils` module provides shared utility functions.

::: quiltx.utils
    options:
      show_root_heading: true
      show_source: true
