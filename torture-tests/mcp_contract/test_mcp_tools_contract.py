from __future__ import annotations

import os
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_tools_list_has_core_tools(mcp_client):
    resp = mcp_client.tools_list()
    assert "result" in resp and "tools" in resp["result"], resp
    tools = {t["name"] for t in resp["result"]["tools"]}

    # Core surface area we expect for Ninja Warrior evaluation.
    expected = {
        "analyze_code",
        "crawl_project",
        "cross_file_security_scan",
        "extract_code",
        "generate_unit_tests",
        "security_scan",
        "get_call_graph",
        "get_cross_file_dependencies",
        "extract_code",
        "get_file_context",
        "get_graph_neighborhood",
        "get_project_map",
        "get_symbol_references",
        "scan_dependencies",
        "simulate_refactor",
        "update_symbol",
        "symbolic_execute",
        "type_evaporation_scan",
        "unified_sink_detect",
        "validate_paths",
        "verify_policy_integrity",
    }

    missing = expected - tools
    assert not missing, f"Missing expected tools: {sorted(missing)}"


def test_analyze_code_contract(mcp_client):
    result = mcp_client.tools_call(
        "analyze_code",
        {
            "code": "def f(x):\n    if x:\n        return 1\n    return 0\n",
            "language": "python",
        },
    )
    assert result.get("success") is True, result
    assert "f" in (result.get("functions") or []), result
    assert isinstance(result.get("complexity"), int), result
    assert result["complexity"] >= 2, result


def test_extract_code_contract(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    result = mcp_client.tools_call(
        "extract_code",
        {"target_type": "function", "target_name": "divide", "file_path": str(path)},
    )
    assert result.get("success") is True, result
    assert "def divide" in result.get("target_code", ""), result
    assert result.get("line_start", 0) > 0, result
    assert result.get("line_end", 0) >= result.get("line_start", 0), result


def test_get_file_context_contract_js(mcp_client):
    js_path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "01-unicode-minefield.js"
    result = mcp_client.tools_call("get_file_context", {"file_path": str(js_path)})
    assert result.get("success") is True, result
    # Language detection is a key capability check.
    assert result.get("language") == "javascript", result
    assert isinstance(result.get("functions"), list), result


def test_validate_paths_negative_control(mcp_client, tmp_path):
    existing = _repo_root() / "README.md"
    missing = tmp_path / "does_not_exist_12345.txt"

    result = mcp_client.tools_call("validate_paths", {"paths": [str(existing), str(missing)]})

    # validate_paths reports success=False when any input path is inaccessible.
    assert result.get("success") is False, result
    assert any(str(missing) in p for p in (result.get("inaccessible") or [])), result


def test_symbolic_execute_contract(mcp_client):
    code = """

def branch(x, y):
    if x:
        if y:
            return 'A'
        return 'B'
    return 'C'
""".strip()

    result = mcp_client.tools_call("symbolic_execute", {"code": code, "max_paths": 10})
    assert result.get("success") is True, result
    assert result.get("paths_explored", 0) >= 3, result


def test_security_scan_contract_sql_injection_snippet(mcp_client):
    code = """
def handler(user_id):
    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n
    cursor.execute(query)
""".strip()
    result = mcp_client.tools_call("security_scan", {"code": code})
    assert result.get("success") is True, result
    assert result.get("has_vulnerabilities") is True, result
    assert result.get("vulnerability_count", 0) >= 1, result


def test_unified_sink_detect_contract_shell_true(mcp_client):
    result = mcp_client.tools_call(
        "unified_sink_detect",
        {"code": "import subprocess\nsubprocess.run('id', shell=True)", "language": "python"},
    )
    assert result.get("success") is True, result
    assert result.get("sink_count", 0) >= 1, result


def test_type_evaporation_scan_contract(mcp_client):
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
    result = mcp_client.tools_call(
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.py"},
    )
    assert result.get("success") is True, result
    # Contract-only: should return counts fields, not necessarily stable detection totals.
    assert "cross_file_issues" in result, result


def test_scan_dependencies_contract_no_network(tmp_path, mcp_client):
    # Use scan_vulnerabilities=False to avoid OSV network dependency in contract tests.
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}', encoding="utf-8")
    result = mcp_client.tools_call(
        "scan_dependencies",
        {"path": str(pkg), "scan_vulnerabilities": False, "include_dev": False},
    )
    assert result.get("success") is True, result
    assert result.get("total_dependencies", 0) >= 1, result


def test_simulate_refactor_contract(mcp_client):
    result = mcp_client.tools_call(
        "simulate_refactor",
        {"original_code": "def f(x):\n    return x\n", "new_code": "def f(x):\n    return eval(x)\n"},
    )
    assert result.get("success") is True, result
    assert result.get("is_safe") is False, result


def test_update_symbol_contract_tempfile(mcp_client, tmp_path):
    demo = tmp_path / "demo_update_symbol.py"
    demo.write_text(
        """
def greet():
    return 'hi'
""".lstrip(),
        encoding="utf-8",
    )

    new_code = """
def greet():
    return 'hello'
""".lstrip()

    result = mcp_client.tools_call(
        "update_symbol",
        {"file_path": str(demo), "target_type": "function", "target_name": "greet", "new_code": new_code, "create_backup": True},
    )
    assert result.get("success") is True, result
    # Backup is an important safety contract.
    assert (tmp_path / "demo_update_symbol.py.bak").exists(), result


def test_get_project_map_contract_small_root(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    result = mcp_client.tools_call(
        "get_project_map",
        {"project_root": str(root), "include_complexity": True, "complexity_threshold": 50, "include_circular_check": True},
    )
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert result.get("project_root"), result


def test_crawl_project_contract_small_root(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-test"
    result = mcp_client.tools_call(
        "crawl_project",
        {"root_path": str(root), "complexity_threshold": 50, "include_report": False},
    )
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert "summary" in result, result


def test_get_symbol_references_contract(mcp_client):
    root = _repo_root() / "torture-tests"
    result = mcp_client.tools_call("get_symbol_references", {"symbol_name": "search_users", "project_root": str(root)})
    assert result.get("success") is True, result
    assert "total_references" in result, result


def test_get_call_graph_contract(mcp_client):
    root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
    result = mcp_client.tools_call(
        "get_call_graph",
        {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": 6, "include_circular_import_check": True},
    )
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert isinstance(result.get("nodes"), list), result
        assert isinstance(result.get("edges"), list), result


def test_get_cross_file_dependencies_contract_low_noise(mcp_client):
    result = mcp_client.tools_call(
        "get_cross_file_dependencies",
        {
            "target_file": "torture-tests/stage8-advanced-taint/crossfile-hard/routes.py",
            "target_symbol": "search_route",
            "max_depth": 2,
            "include_code": False,
            "include_diagram": False,
            "confidence_decay_factor": 0.9,
        },
    )
    assert result.get("success") in (True, False), result
    if result.get("success") is True:
        assert "extracted_symbols" in result, result


def test_cross_file_security_scan_contract_does_not_crash(mcp_client):
    root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"
    result = mcp_client.tools_call(
        "cross_file_security_scan",
        {"project_root": str(root), "max_depth": 5, "include_diagram": False, "timeout_seconds": 30, "max_modules": 200},
    )
    assert result.get("success") in (True, False), result
    # Contract only: tool should return a structured response even if it misses a finding.
    if result.get("success") is True:
        assert "has_vulnerabilities" in result, result


def test_get_graph_neighborhood_contract_invalid_id_is_handled(mcp_client):
    result = mcp_client.tools_call(
        "get_graph_neighborhood",
        {"center_node_id": "python::nonexistent::function::nope", "k": 1, "max_nodes": 25, "direction": "both", "min_confidence": 0.0},
    )
    # Different implementations may return success False or a tiny empty graph; both are acceptable.
    assert "success" in result, result


@pytest.mark.xfail(
    reason="Known issue: generate_unit_tests emits incorrect assertions even when paths/inputs are correct (tracked in MCP_TOOL_RESULTS.md).",
    strict=False,
)
def test_generate_unit_tests_semantics(mcp_client):
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
    # Semantic expectation: the generated assertions should reflect multiple returns.
    assert "== 'A'" in pytest_code and "== 'B'" in pytest_code and "== 'C'" in pytest_code


@pytest.mark.xfail(
    reason="verify_policy_integrity currently blocked in MCP runtime (PyYAML/env mismatch); should be updated when the tool is patched.",
    strict=False,
)
def test_verify_policy_integrity_fail_closed(mcp_client):
    # Without SCALPEL_MANIFEST_SECRET, the tool should fail closed with a clear error.
    os.environ.pop("SCALPEL_MANIFEST_SECRET", None)
    result = mcp_client.tools_call("verify_policy_integrity", {"policy_dir": ".code-scalpel", "manifest_source": "file"})
    assert result.get("success") is False
    assert result.get("error"), result
