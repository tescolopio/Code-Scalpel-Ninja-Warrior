from __future__ import annotations

import time
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _timed(mcp_client, tool: str, args: dict, *, max_seconds: float):
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    assert elapsed <= max_seconds, {"tool": tool, "elapsed": elapsed, "result": result}
    return result


def test_get_call_graph_small_fixture_bounded(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    result = _timed(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": 6, "include_circular_import_check": True},
        max_seconds=20,
    )
    assert result.get("success") in (True, False), result


def test_get_project_map_small_root_bounded(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    result = _timed(
        mcp_client,
        "get_project_map",
        {"project_root": str(root), "include_complexity": True, "complexity_threshold": 50, "include_circular_check": True},
        max_seconds=25,
    )
    assert result.get("success") in (True, False), result


def test_crawl_project_small_root_bounded(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    result = _timed(
        mcp_client,
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 50, "include_report": False},
        max_seconds=25,
    )
    assert result.get("success") in (True, False), result


def test_get_graph_neighborhood_invalid_id_fast_fail(mcp_client):
    # Should not hang.
    result = _timed(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": "python::nonexistent::function::nope", "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=10,
    )
    assert "success" in result, result


def test_get_cross_file_dependencies_small_depth_bounded(mcp_client):
    result = _timed(
        mcp_client,
        "get_cross_file_dependencies",
        {
            "target_file": "torture-tests/stage8-advanced-taint/crossfile-hard/routes.py",
            "target_symbol": "search_route",
            "max_depth": 2,
            "include_code": False,
            "include_diagram": False,
            "confidence_decay_factor": 0.9,
        },
        max_seconds=30,
    )
    assert result.get("success") in (True, False), result


def test_cross_file_security_scan_returns_structured(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    # Tighten timeout to enforce a bound.
    result = _timed(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 5, "include_diagram": False, "timeout_seconds": 20, "max_modules": 200},
        max_seconds=30,
    )
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert "has_vulnerabilities" in result, result
