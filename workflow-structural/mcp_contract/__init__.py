"""Pytest-based contract tests for the Code Scalpel MCP server.

These tests are intentionally *tool-specific* and focus on:
- capability discovery (tools/list)
- request/response contract stability (keys, types, invariants)
- boundary/negative controls (missing paths, malformed inputs)

They are not a replacement for the stage-based gauntlet; they are a fast,
repeatable regression suite for MCP tool behavior.
"""
