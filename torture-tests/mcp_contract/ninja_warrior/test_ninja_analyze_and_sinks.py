from __future__ import annotations

import time

import pytest


def _timed_call(mcp_client, tool: str, args: dict, *, max_seconds: float | None = None):
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    if max_seconds is not None:
        assert elapsed <= max_seconds, {"tool": tool, "elapsed": elapsed, "result": result}
    return result, elapsed


def test_analyze_code_python_edge_complexity(mcp_client):
    code = """
import math

def f(x):
    if x > 10:
        if x % 2 == 0:
            return 1
        return 2
    elif x == 10:
        return 3
    return 4
""".strip()

    result, _ = _timed_call(mcp_client, "analyze_code", {"code": code, "language": "python"}, max_seconds=10)
    assert result.get("success") is True, result
    assert "f" in (result.get("functions") or []), result
    # Complexity should be >= number of branches (implementation-specific exact value).
    assert isinstance(result.get("complexity"), int), result
    assert result["complexity"] >= 4, result


def test_analyze_code_invalid_python_negative_control(mcp_client):
    bad = "def f(:\n    pass\n"
    result, _ = _timed_call(mcp_client, "analyze_code", {"code": bad, "language": "python"}, max_seconds=10)
    # Contract: should fail safely (either success False, or return an error envelope).
    if isinstance(result, dict) and "error" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_unified_sink_detect_thresholds(mcp_client):
    code = "import subprocess\nsubprocess.run('id', shell=True)\n"

    low, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "python", "min_confidence": 0.0}, max_seconds=10)
    assert low.get("success") is True, low
    assert low.get("sink_count", 0) >= 1, low

    high, _ = _timed_call(mcp_client, "unified_sink_detect", {"code": code, "language": "python", "min_confidence": 0.99}, max_seconds=10)
    assert high.get("success") is True, high
    # At very high threshold, implementations may filter all sinks; accept either.
    assert "sink_count" in high, high


def test_security_scan_safe_negative_control(mcp_client):
    safe = """

def handler(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
""".strip()

    result, _ = _timed_call(mcp_client, "security_scan", {"code": safe}, max_seconds=15)
    assert result.get("success") is True, result
    assert result.get("has_vulnerabilities") is False, result


def test_security_scan_sqli_positive_control(mcp_client):
    vuln = """

def handler(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
""".strip()

    result, _ = _timed_call(mcp_client, "security_scan", {"code": vuln}, max_seconds=15)
    assert result.get("success") is True, result
    assert result.get("has_vulnerabilities") is True, result
    assert result.get("vulnerability_count", 0) >= 1, result
