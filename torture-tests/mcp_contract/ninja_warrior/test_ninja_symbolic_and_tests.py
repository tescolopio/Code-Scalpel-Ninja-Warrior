from __future__ import annotations

import time

import pytest


def test_symbolic_execute_reaches_all_paths(mcp_client):
    code = """

def branch(x, y):
    if x:
        if y:
            return 'A'
        return 'B'
    return 'C'
""".strip()

    start = time.monotonic()
    result = mcp_client.tools_call("symbolic_execute", {"code": code, "max_paths": 10})
    elapsed = time.monotonic() - start
    assert elapsed <= 20, {"elapsed": elapsed, "result": result}

    assert result.get("success") is True, result
    assert result.get("paths_explored", 0) >= 3, result


def test_simulate_refactor_patch_argument(mcp_client):
    # Patch-based simulation should work and detect a dangerous sink.
    patch = """
--- a/demo.py
+++ b/demo.py
@@
-def f(x):
-    return x
+def f(x):
+    return eval(x)
""".lstrip()

    result = mcp_client.tools_call("simulate_refactor", {"original_code": "def f(x):\n    return x\n", "patch": patch, "strict_mode": False})
    assert result.get("success") is True, result
    assert result.get("is_safe") is False, result


@pytest.mark.xfail(
    reason="Known issue: generate_unit_tests can emit incorrect assertions; keep as evidence without masking other tools.",
    strict=False,
)
def test_generate_unit_tests_assertions_match_returns(mcp_client):
    code = """

def branch(x, y):
    if x:
        if y:
            return 'A'
        return 'B'
    return 'C'
""".strip()

    result = mcp_client.tools_call("generate_unit_tests", {"code": code, "framework": "pytest"})
    assert result.get("success") is True, result
    pytest_code = result.get("pytest_code", "")
    assert "== 'A'" in pytest_code and "== 'B'" in pytest_code and "== 'C'" in pytest_code
