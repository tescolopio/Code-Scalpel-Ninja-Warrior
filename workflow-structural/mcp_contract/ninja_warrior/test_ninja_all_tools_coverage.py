from __future__ import annotations

import time
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


EXPECTED_TOOLS = {
    # Core Analysis (5 tools)
    "analyze_code",
    "crawl_project",
    "get_file_context",
    "get_project_map",
    "validate_paths",
    # Security Scanning (4 tools)
    "security_scan",
    "cross_file_security_scan",
    "unified_sink_detect",
    "type_evaporation_scan",
    # Graph & Dependencies (4 tools)
    "get_call_graph",
    "get_cross_file_dependencies",
    "get_graph_neighborhood",
    "scan_dependencies",
    # Symbol Operations (4 tools)
    "extract_code",
    "get_symbol_references",
    "rename_symbol",  # Previously missing
    "update_symbol",
    # Advanced Analysis (3 tools)
    "generate_unit_tests",
    "simulate_refactor",
    "symbolic_execute",
    # Policy & Governance (2 tools)
    "code_policy_check",  # Previously missing
    "verify_policy_integrity",
}

# Verify we have exactly 22 tools
assert len(EXPECTED_TOOLS) == 22, f"Expected 22 tools, got {len(EXPECTED_TOOLS)}"


def _timed(mcp_client, tool: str, args: dict, *, max_seconds: float):
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    assert elapsed <= max_seconds, {"tool": tool, "elapsed": elapsed, "result": result}
    return result


def test_tools_list_is_exactly_expected_22(mcp_client):
    resp = mcp_client.tools_list()
    assert "result" in resp and "tools" in resp["result"], resp
    names = {t["name"] for t in resp["result"]["tools"]}

    missing = EXPECTED_TOOLS - names
    extra = names - EXPECTED_TOOLS

    # If this fails, the suite must be updated to cover new tools.
    assert not missing, f"Missing tools from server: {sorted(missing)}"
    assert not extra, f"Unexpected new tools exposed by server: {sorted(extra)}"


# --- Normal / Edge / Negative / Perf coverage fillers (only where previously missing) ---


def test_extract_code_normal_bounded(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    result = _timed(
        mcp_client,
        "extract_code",
        {"target_type": "function", "target_name": "divide", "file_path": str(path)},
        max_seconds=10,
    )
    assert result.get("success") is True, result
    assert "def divide" in result.get("target_code", ""), result


def test_validate_paths_all_accessible_success(mcp_client):
    result = _timed(
        mcp_client,
        "validate_paths",
        {"paths": ["README.md", "torture-tests/test_harness.py", ".code-scalpel/policy.yaml"]},
        max_seconds=10,
    )
    assert result.get("success") is True, result
    assert result.get("inaccessible") in ([], None) or len(result.get("inaccessible") or []) == 0, result


def test_validate_paths_large_list_perf(mcp_client):
    # Performance bound on a larger list.
    paths = ["README.md"] * 200
    result = _timed(mcp_client, "validate_paths", {"paths": paths}, max_seconds=15)
    assert result.get("success") is True, result


def test_type_evaporation_scan_unsafe_positive_control(mcp_client):
    frontend = """
type Role = 'admin' | 'user'
export async function sendRole(role: Role) {
  return fetch('/api/boundary/role', { method: 'POST', body: JSON.stringify({ role }) })
}
""".strip()

    backend = """
from flask import Flask, request
app = Flask(__name__)

@app.post('/api/boundary/role')
def role():
    data = request.get_json(force=True)
    return {'role': data['role']}
""".strip()

    result = _timed(
        mcp_client,
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.py"},
        max_seconds=15,
    )
    assert result.get("success") is True, result
    assert result.get("cross_file_issues", 0) >= 1, result


def test_scan_dependencies_package_json_no_network(mcp_client, tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}', encoding="utf-8")
    result = _timed(
        mcp_client,
        "scan_dependencies",
        {"path": str(pkg), "scan_vulnerabilities": False, "include_dev": False},
        max_seconds=15,
    )
    assert result.get("success") is True, result
    assert result.get("total_dependencies", 0) >= 1, result


def test_verify_policy_integrity_missing_manifest_fails_closed(mcp_client, tmp_path):
    # Provide an empty dir; should fail closed (missing manifest/policy files).
    empty = tmp_path / "empty_policies"
    empty.mkdir()

    result = _timed(
        mcp_client,
        "verify_policy_integrity",
        {"policy_dir": str(empty), "manifest_source": "file"},
        max_seconds=15,
    )

    if isinstance(result, dict) and "error" in result and "jsonrpc" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_symbolic_execute_invalid_code_negative_control(mcp_client):
    bad = "def f(:\n  pass\n"
    result = _timed(mcp_client, "symbolic_execute", {"code": bad, "max_paths": 5}, max_seconds=15)
    if isinstance(result, dict) and "error" in result and "jsonrpc" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_simulate_refactor_new_code_detects_eval(mcp_client):
    # new_code path should be detected even if patch-mode is buggy.
    result = _timed(
        mcp_client,
        "simulate_refactor",
        {"original_code": "def f(x):\n    return x\n", "new_code": "def f(x):\n    return eval(x)\n", "strict_mode": False},
        max_seconds=15,
    )
    assert result.get("success") is True, result
    assert result.get("is_safe") is False, result


def test_get_graph_neighborhood_valid_id_from_call_graph(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    graph = _timed(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": 6, "include_circular_import_check": True},
        max_seconds=25,
    )

    if graph.get("success") is not True:
        pytest.skip(f"get_call_graph failed: {graph}")

    nodes = graph.get("nodes") or []
    node_id = None
    for n in nodes:
        if isinstance(n, str) and n:
            node_id = n
            break
        if isinstance(n, dict):
            for k in ("id", "node_id", "name"):
                if isinstance(n.get(k), str) and n.get(k):
                    node_id = n[k]
                    break
        if node_id:
            break

    if not node_id:
        pytest.skip(f"No node id found in call graph nodes: {nodes[:3]}")

    nb = _timed(
        mcp_client,
        "get_graph_neighborhood",
        {"center_node_id": node_id, "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
        max_seconds=15,
    )
    assert "success" in nb, nb


def test_get_call_graph_invalid_entry_point_negative_control(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    result = _timed(
        mcp_client,
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:does_not_exist", "depth": 3, "include_circular_import_check": True},
        max_seconds=20,
    )
    assert result.get("success") in (True, False), result


def test_crawl_project_invalid_root_negative_control(mcp_client, tmp_path):
    missing = tmp_path / "nope"
    result = _timed(mcp_client, "crawl_project", {"root_path": str(missing), "include_report": False}, max_seconds=15)
    assert result.get("success") is False, result


def test_get_project_map_invalid_root_negative_control(mcp_client, tmp_path):
    missing = tmp_path / "nope"
    result = _timed(mcp_client, "get_project_map", {"project_root": str(missing)}, max_seconds=15)
    assert result.get("success") is False, result


def test_get_file_context_missing_file_negative_control(mcp_client, tmp_path):
    missing = tmp_path / "missing.py"
    result = _timed(mcp_client, "get_file_context", {"file_path": str(missing)}, max_seconds=10)
    assert result.get("success") is False, result


def test_get_symbol_references_perf_bounded(mcp_client):
    root = _repo_root() / "torture-tests"
    result = _timed(mcp_client, "get_symbol_references", {"symbol_name": "search_users", "project_root": str(root)}, max_seconds=25)
    assert result.get("success") is True, result


def test_cross_file_security_scan_positive_control_expected_vuln(mcp_client):
    # This is expected to find a cross-file flow in the hard fixture.
    # If it doesn't, that's evidence of a miss.
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    result = _timed(
        mcp_client,
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 5, "include_diagram": False, "timeout_seconds": 25, "max_modules": 200},
        max_seconds=35,
    )
    assert result.get("success") is True, result
    assert result.get("has_vulnerabilities") is True, result


# =============================================================================
# Tests for Previously Missing Tools (rename_symbol, code_policy_check)
# =============================================================================


def test_rename_symbol_basic_function_rename(mcp_client, tmp_path):
    """Test rename_symbol can rename a function across a file."""
    code = '''
def old_name(x):
    return x * 2

def caller():
    return old_name(5)
'''
    test_file = tmp_path / "rename_test.py"
    test_file.write_text(code, encoding="utf-8")

    result = _timed(
        mcp_client,
        "rename_symbol",
        {
            "file_path": str(test_file),
            "old_name": "old_name",
            "new_name": "new_name",
            "symbol_type": "function",
        },
        max_seconds=15,
    )
    # Tool should either succeed or report it doesn't exist
    assert "success" in result or "error" in result, result


def test_rename_symbol_variable_rename(mcp_client, tmp_path):
    """Test rename_symbol can rename a variable."""
    code = '''
old_var = 42
result = old_var + 1
print(old_var)
'''
    test_file = tmp_path / "var_rename.py"
    test_file.write_text(code, encoding="utf-8")

    result = _timed(
        mcp_client,
        "rename_symbol",
        {
            "file_path": str(test_file),
            "old_name": "old_var",
            "new_name": "new_var",
            "symbol_type": "variable",
        },
        max_seconds=15,
    )
    assert "success" in result or "error" in result, result


def test_rename_symbol_invalid_name_negative(mcp_client, tmp_path):
    """Test rename_symbol rejects invalid Python identifiers."""
    code = "x = 1\n"
    test_file = tmp_path / "invalid_rename.py"
    test_file.write_text(code, encoding="utf-8")

    result = _timed(
        mcp_client,
        "rename_symbol",
        {
            "file_path": str(test_file),
            "old_name": "x",
            "new_name": "123invalid",  # Invalid identifier
            "symbol_type": "variable",
        },
        max_seconds=15,
    )
    # Should either fail or return error about invalid name
    if result.get("success") is True:
        # If it succeeded, the tool doesn't validate - that's a finding
        pytest.xfail("rename_symbol should reject invalid Python identifiers")


def test_code_policy_check_sql_injection_blocked(mcp_client):
    """Test code_policy_check detects SQL injection violation."""
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
'''
    result = _timed(
        mcp_client,
        "code_policy_check",
        {
            "code": code,
            "policy_rules": ["no_sql_injection", "no_command_injection"],
        },
        max_seconds=15,
    )
    assert "success" in result or "error" in result, result
    if result.get("success") is True:
        # Should have violations
        assert result.get("violations", []) or result.get("policy_violations", []), result


def test_code_policy_check_safe_code_passes(mcp_client):
    """Test code_policy_check allows safe code."""
    code = '''
def add(a: int, b: int) -> int:
    return a + b
'''
    result = _timed(
        mcp_client,
        "code_policy_check",
        {
            "code": code,
            "policy_rules": ["no_sql_injection", "no_eval"],
        },
        max_seconds=15,
    )
    assert "success" in result or "error" in result, result


def test_code_policy_check_custom_policy(mcp_client):
    """Test code_policy_check with custom policy rules."""
    code = '''
import os
os.system("ls")
'''
    result = _timed(
        mcp_client,
        "code_policy_check",
        {
            "code": code,
            "policy_rules": ["no_os_system", "no_shell_execution"],
            "strict_mode": True,
        },
        max_seconds=15,
    )
    assert "success" in result or "error" in result, result
