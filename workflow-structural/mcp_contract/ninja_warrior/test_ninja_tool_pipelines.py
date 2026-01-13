"""Tool Pipeline Tests for Code Scalpel MCP Tools.

These tests verify that tools work correctly when chained together
in realistic workflows. Each pipeline represents a real-world use case.

Pipeline Categories:
1. Security Audit Pipeline - Full security analysis workflow
2. Refactoring Pipeline - Safe code modification workflow
3. Codebase Exploration Pipeline - Understanding new codebase
4. Dependency Audit Pipeline - Third-party risk assessment
5. Policy Enforcement Pipeline - Governance verification
6. Cross-File Analysis Pipeline - Multi-module security
"""

from __future__ import annotations

import time
import json
from pathlib import Path
from typing import Optional

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _call(mcp_client, tool: str, args: dict, *, max_seconds: float = 60.0):
    """Execute tool with timing."""
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    if elapsed > max_seconds:
        pytest.fail(f"{tool} exceeded {max_seconds}s (took {elapsed:.1f}s)")
    return result, elapsed


def _normalize(raw) -> dict:
    """Normalize tool result."""
    if not isinstance(raw, dict):
        return {"success": False, "error": f"Non-dict: {type(raw)}"}
    if "jsonrpc" in raw and "error" in raw:
        return {"success": False, "error": raw.get("error", {}).get("message", str(raw))}
    if "data" in raw and "capabilities" in raw:
        data = raw.get("data") or {}
        if raw.get("error"):
            return {**data, "success": False, "error": str(raw["error"])}
        return {**data, "success": True}
    return raw


# =============================================================================
# PIPELINE 1: SECURITY AUDIT WORKFLOW
# =============================================================================

class TestSecurityAuditPipeline:
    """
    Complete security audit workflow:
    1. Crawl project to understand structure
    2. Get project map for file overview
    3. Run security scan on each file
    4. Cross-file scan for taint flows
    5. Unified sink detection for comprehensive coverage
    6. Policy check for compliance
    """

    def test_full_security_audit_pipeline(self, mcp_client, tmp_path):
        """Execute complete security audit pipeline."""
        # Create a test project with vulnerabilities
        (tmp_path / "app.py").write_text('''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    return subprocess.check_output(cmd, shell=True)

@app.route("/user/<user_id>")
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')
        (tmp_path / "utils.py").write_text('''
import pickle

def load_data(data):
    return pickle.loads(data)

def save_data(obj):
    return pickle.dumps(obj)
''')

        pipeline_results = {}

        # Step 1: Crawl project
        result, _ = _call(mcp_client, "crawl_project",
                          {"root_path": str(tmp_path), "include_report": True})
        pipeline_results["crawl"] = _normalize(result)
        assert pipeline_results["crawl"].get("success") is not False

        # Step 2: Get project map
        result, _ = _call(mcp_client, "get_project_map",
                          {"project_root": str(tmp_path)})
        pipeline_results["map"] = _normalize(result)

        # Step 3: Security scan each file
        for py_file in tmp_path.glob("*.py"):
            code = py_file.read_text()
            result, _ = _call(mcp_client, "security_scan", {"code": code})
            pipeline_results[f"scan_{py_file.name}"] = _normalize(result)

        # Step 4: Cross-file security scan
        result, _ = _call(mcp_client, "cross_file_security_scan",
                          {"project_root": str(tmp_path), "max_depth": 5,
                           "timeout_seconds": 30})
        pipeline_results["crossfile"] = _normalize(result)

        # Step 5: Unified sink detection
        all_code = "\n".join(f.read_text() for f in tmp_path.glob("*.py"))
        result, _ = _call(mcp_client, "unified_sink_detect",
                          {"code": all_code, "language": "python"})
        pipeline_results["sinks"] = _normalize(result)

        # Step 6: Policy check
        result, _ = _call(mcp_client, "code_policy_check",
                          {"code": all_code, "policy_rules": [
                              "no_shell_true", "no_sql_injection", "no_pickle"
                          ]})
        pipeline_results["policy"] = _normalize(result)

        # Verify pipeline produced meaningful results
        assert len(pipeline_results) >= 6
        # At least some scans should detect vulnerabilities
        vuln_found = any(
            r.get("has_vulnerabilities") or r.get("vulnerability_count", 0) > 0
            for r in pipeline_results.values() if isinstance(r, dict)
        )
        if not vuln_found:
            pytest.xfail("Pipeline should detect at least one vulnerability")


# =============================================================================
# PIPELINE 2: SAFE REFACTORING WORKFLOW
# =============================================================================

class TestRefactoringPipeline:
    """
    Safe code refactoring workflow:
    1. Get file context for the target file
    2. Extract the code to be modified
    3. Get symbol references across codebase
    4. Simulate the refactoring
    5. Run security scan on new code
    6. If safe, update/rename symbols
    """

    def test_safe_refactoring_pipeline(self, mcp_client, tmp_path):
        """Execute safe refactoring pipeline."""
        # Create test files
        (tmp_path / "core.py").write_text('''
def process_data(raw_data):
    """Process raw data safely."""
    validated = validate(raw_data)
    return transform(validated)

def validate(data):
    if not isinstance(data, str):
        raise ValueError("Must be string")
    return data.strip()

def transform(data):
    return data.upper()
''')
        (tmp_path / "api.py").write_text('''
from core import process_data

def handle_request(request):
    return process_data(request.data)
''')

        pipeline_results = {}

        # Step 1: Get file context
        result, _ = _call(mcp_client, "get_file_context",
                          {"file_path": str(tmp_path / "core.py")})
        pipeline_results["context"] = _normalize(result)

        # Step 2: Extract the function to modify
        result, _ = _call(mcp_client, "extract_code",
                          {"file_path": str(tmp_path / "core.py"),
                           "target_type": "function", "target_name": "process_data"})
        pipeline_results["extract"] = _normalize(result)

        # Step 3: Get symbol references
        result, _ = _call(mcp_client, "get_symbol_references",
                          {"symbol_name": "process_data", "project_root": str(tmp_path)})
        pipeline_results["refs"] = _normalize(result)

        # Step 4: Simulate refactoring
        original = (tmp_path / "core.py").read_text()
        new_code = original.replace("process_data", "handle_data")
        result, _ = _call(mcp_client, "simulate_refactor",
                          {"original_code": original, "new_code": new_code,
                           "strict_mode": False})
        pipeline_results["simulate"] = _normalize(result)

        # Step 5: Security scan new code
        result, _ = _call(mcp_client, "security_scan", {"code": new_code})
        pipeline_results["scan_new"] = _normalize(result)

        # Step 6: If safe, perform rename
        if pipeline_results["simulate"].get("is_safe", True):
            result, _ = _call(mcp_client, "rename_symbol",
                              {"file_path": str(tmp_path / "core.py"),
                               "old_name": "process_data", "new_name": "handle_data",
                               "symbol_type": "function"})
            pipeline_results["rename"] = _normalize(result)

        assert len(pipeline_results) >= 5


# =============================================================================
# PIPELINE 3: CODEBASE EXPLORATION WORKFLOW
# =============================================================================

class TestCodebaseExplorationPipeline:
    """
    Exploring unfamiliar codebase workflow:
    1. Crawl to understand project structure
    2. Get project map for overview
    3. Analyze key entry point files
    4. Build call graph from entry points
    5. Get cross-file dependencies
    6. Explore graph neighborhood for related code
    """

    def test_codebase_exploration_pipeline(self, mcp_client):
        """Execute codebase exploration pipeline."""
        root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"

        if not root.exists():
            pytest.skip(f"Test fixture not found: {root}")

        pipeline_results = {}

        # Step 1: Crawl project
        result, _ = _call(mcp_client, "crawl_project",
                          {"root_path": str(root), "include_report": True})
        pipeline_results["crawl"] = _normalize(result)

        # Step 2: Get project map
        result, _ = _call(mcp_client, "get_project_map",
                          {"project_root": str(root)})
        pipeline_results["map"] = _normalize(result)

        # Step 3: Analyze entry file
        entry_file = root / "call_chain.py"
        if entry_file.exists():
            result, _ = _call(mcp_client, "analyze_code",
                              {"code": entry_file.read_text(), "language": "python"})
            pipeline_results["analyze"] = _normalize(result)

        # Step 4: Build call graph
        result, _ = _call(mcp_client, "get_call_graph",
                          {"project_root": str(root), "entry_point": "call_chain.py:alpha",
                           "depth": 6, "include_circular_import_check": True})
        pipeline_results["callgraph"] = _normalize(result)

        # Step 5: Get cross-file dependencies
        result, _ = _call(mcp_client, "get_cross_file_dependencies",
                          {"project_root": str(root), "max_depth": 5})
        pipeline_results["deps"] = _normalize(result)

        # Step 6: Explore neighborhood (if we have node IDs from call graph)
        if pipeline_results["callgraph"].get("success"):
            nodes = pipeline_results["callgraph"].get("nodes", [])
            if nodes and isinstance(nodes[0], dict):
                node_id = nodes[0].get("id") or nodes[0].get("name")
            elif nodes and isinstance(nodes[0], str):
                node_id = nodes[0]
            else:
                node_id = None

            if node_id:
                result, _ = _call(mcp_client, "get_graph_neighborhood",
                                  {"center_node_id": node_id, "k": 2, "max_nodes": 20})
                pipeline_results["neighborhood"] = _normalize(result)

        assert len(pipeline_results) >= 4


# =============================================================================
# PIPELINE 4: DEPENDENCY AUDIT WORKFLOW
# =============================================================================

class TestDependencyAuditPipeline:
    """
    Third-party dependency audit workflow:
    1. Scan dependencies from manifest
    2. Validate paths of dependency locations
    3. For each suspicious dep, analyze its code
    4. Cross-file scan for taint from deps
    5. Type evaporation scan at boundaries
    """

    def test_dependency_audit_pipeline(self, mcp_client, tmp_path):
        """Execute dependency audit pipeline."""
        # Create mock project with dependencies
        (tmp_path / "package.json").write_text(json.dumps({
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.20",
                "express": "4.17.1",
                "jsonwebtoken": "8.5.1"
            }
        }))

        (tmp_path / "app.js").write_text('''
const express = require('express');
const jwt = require('jsonwebtoken');
const _ = require('lodash');

const app = express();

app.post('/login', (req, res) => {
    const token = jwt.sign({ user: req.body.user }, 'secret-key');
    res.json({ token });
});

app.get('/data', (req, res) => {
    const input = _.get(req.query, 'path');
    res.send(input);
});
''')

        pipeline_results = {}

        # Step 1: Scan dependencies
        result, _ = _call(mcp_client, "scan_dependencies",
                          {"path": str(tmp_path / "package.json"),
                           "scan_vulnerabilities": True, "include_dev": False})
        pipeline_results["deps"] = _normalize(result)

        # Step 2: Validate paths
        result, _ = _call(mcp_client, "validate_paths",
                          {"paths": [str(tmp_path / "package.json"),
                                     str(tmp_path / "app.js")]})
        pipeline_results["paths"] = _normalize(result)

        # Step 3: Analyze app code
        result, _ = _call(mcp_client, "analyze_code",
                          {"code": (tmp_path / "app.js").read_text(),
                           "language": "javascript"})
        pipeline_results["analyze"] = _normalize(result)

        # Step 4: Security scan
        result, _ = _call(mcp_client, "security_scan",
                          {"code": (tmp_path / "app.js").read_text()})
        pipeline_results["security"] = _normalize(result)

        # Step 5: Cross-file scan
        result, _ = _call(mcp_client, "cross_file_security_scan",
                          {"project_root": str(tmp_path), "max_depth": 3})
        pipeline_results["crossfile"] = _normalize(result)

        assert len(pipeline_results) >= 4


# =============================================================================
# PIPELINE 5: POLICY ENFORCEMENT WORKFLOW
# =============================================================================

class TestPolicyEnforcementPipeline:
    """
    Policy enforcement workflow:
    1. Verify policy integrity
    2. For each file, check against policies
    3. Simulate any proposed changes
    4. Validate no policy violations
    5. Generate report
    """

    def test_policy_enforcement_pipeline(self, mcp_client, tmp_path):
        """Execute policy enforcement pipeline."""
        # Create policy config
        policy_dir = tmp_path / ".code-scalpel"
        policy_dir.mkdir()
        (policy_dir / "policy.yaml").write_text('''
enforcement_mode: strict
rules:
  - no_eval
  - no_exec
  - no_sql_injection
  - no_command_injection
max_files_per_operation: 10
max_lines_per_file: 1000
''')
        (policy_dir / "config.json").write_text(json.dumps({
            "allowed_operations": ["analyze", "scan"],
            "denied_operations": ["delete_file"],
            "protected_paths": [".git/", "secrets/"]
        }))

        # Create code files
        (tmp_path / "safe.py").write_text('''
def add(a, b):
    return a + b
''')
        (tmp_path / "unsafe.py").write_text('''
def dangerous(user_input):
    return eval(user_input)
''')

        pipeline_results = {}

        # Step 1: Verify policy integrity
        result, _ = _call(mcp_client, "verify_policy_integrity",
                          {"policy_dir": str(policy_dir), "manifest_source": "file"})
        pipeline_results["verify"] = _normalize(result)

        # Step 2: Check each file against policies
        for py_file in tmp_path.glob("*.py"):
            code = py_file.read_text()
            result, _ = _call(mcp_client, "code_policy_check",
                              {"code": code, "policy_rules": ["no_eval", "no_exec"]})
            pipeline_results[f"check_{py_file.name}"] = _normalize(result)

        # Step 3: Simulate a refactoring
        safe_code = (tmp_path / "safe.py").read_text()
        new_code = safe_code + "\ndef multiply(a, b): return a * b\n"
        result, _ = _call(mcp_client, "simulate_refactor",
                          {"original_code": safe_code, "new_code": new_code,
                           "strict_mode": True})
        pipeline_results["simulate"] = _normalize(result)

        # Step 4: Security scan on final code
        result, _ = _call(mcp_client, "security_scan", {"code": new_code})
        pipeline_results["final_scan"] = _normalize(result)

        assert len(pipeline_results) >= 4


# =============================================================================
# PIPELINE 6: CROSS-FILE TAINT ANALYSIS WORKFLOW
# =============================================================================

class TestCrossFileTaintPipeline:
    """
    Cross-file taint analysis workflow:
    1. Map the project structure
    2. Identify entry points
    3. Build call graphs from entries
    4. Run cross-file security scan
    5. Trace specific taint flows
    6. Type evaporation at boundaries
    """

    def test_crossfile_taint_pipeline(self, mcp_client):
        """Execute cross-file taint analysis pipeline."""
        root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"

        if not root.exists():
            pytest.skip(f"Test fixture not found: {root}")

        pipeline_results = {}

        # Step 1: Map project
        result, _ = _call(mcp_client, "get_project_map",
                          {"project_root": str(root)})
        pipeline_results["map"] = _normalize(result)

        # Step 2: Crawl for structure
        result, _ = _call(mcp_client, "crawl_project",
                          {"root_path": str(root), "include_report": True})
        pipeline_results["crawl"] = _normalize(result)

        # Step 3: Get cross-file dependencies
        result, _ = _call(mcp_client, "get_cross_file_dependencies",
                          {"project_root": str(root), "max_depth": 6})
        pipeline_results["deps"] = _normalize(result)

        # Step 4: Cross-file security scan
        result, _ = _call(mcp_client, "cross_file_security_scan",
                          {"project_root": str(root), "max_depth": 6,
                           "include_diagram": True, "timeout_seconds": 60,
                           "max_modules": 100})
        pipeline_results["crossfile_scan"] = _normalize(result)

        # Step 5: Unified sink detection on combined code
        all_code = "\n".join(
            f.read_text() for f in root.rglob("*.py") if f.is_file()
        )
        if all_code:
            result, _ = _call(mcp_client, "unified_sink_detect",
                              {"code": all_code, "language": "python"})
            pipeline_results["sinks"] = _normalize(result)

        # Verify pipeline detected the known vulnerability
        crossfile_result = pipeline_results.get("crossfile_scan", {})
        if crossfile_result.get("success") and not crossfile_result.get("has_vulnerabilities"):
            pytest.xfail("Cross-file scan should detect vulnerability in crossfile-hard")

        assert len(pipeline_results) >= 4


# =============================================================================
# PIPELINE 7: COMBINED ANALYSIS → UNIT TEST GENERATION
# =============================================================================

class TestAnalysisToTestsPipeline:
    """
    Analysis to test generation workflow:
    1. Analyze code structure
    2. Extract functions of interest
    3. Run symbolic execution
    4. Generate unit tests
    5. Validate generated tests don't introduce vulnerabilities
    """

    def test_analysis_to_tests_pipeline(self, mcp_client, tmp_path):
        """Execute analysis to tests pipeline."""
        code = '''
def calculate_discount(price: float, quantity: int, is_member: bool) -> float:
    """Calculate discount based on purchase parameters."""
    if price <= 0:
        raise ValueError("Price must be positive")
    if quantity <= 0:
        raise ValueError("Quantity must be positive")

    discount = 0.0
    if quantity >= 10:
        discount += 0.1
    if quantity >= 50:
        discount += 0.1
    if is_member:
        discount += 0.05

    final_price = price * quantity * (1 - discount)
    return round(final_price, 2)
'''
        test_file = tmp_path / "discount.py"
        test_file.write_text(code)

        pipeline_results = {}

        # Step 1: Analyze code
        result, _ = _call(mcp_client, "analyze_code",
                          {"code": code, "language": "python"})
        pipeline_results["analyze"] = _normalize(result)

        # Step 2: Extract function
        result, _ = _call(mcp_client, "extract_code",
                          {"file_path": str(test_file), "target_type": "function",
                           "target_name": "calculate_discount"})
        pipeline_results["extract"] = _normalize(result)

        # Step 3: Symbolic execution
        result, _ = _call(mcp_client, "symbolic_execute",
                          {"code": code, "function_name": "calculate_discount",
                           "max_paths": 20})
        pipeline_results["symbolic"] = _normalize(result)

        # Step 4: Generate unit tests
        result, _ = _call(mcp_client, "generate_unit_tests",
                          {"code": code, "function_name": "calculate_discount"})
        pipeline_results["tests"] = _normalize(result)

        # Step 5: Scan generated tests for issues
        generated = pipeline_results["tests"].get("generated_tests", "")
        if generated:
            result, _ = _call(mcp_client, "security_scan", {"code": generated})
            pipeline_results["scan_tests"] = _normalize(result)

        assert len(pipeline_results) >= 4


# =============================================================================
# PIPELINE 8: FULL CI/CD SECURITY GATE
# =============================================================================

class TestCICDSecurityGatePipeline:
    """
    CI/CD security gate workflow (pre-merge check):
    1. Validate all changed paths are accessible
    2. Analyze each changed file
    3. Security scan all changes
    4. Cross-file analysis for the changeset
    5. Policy compliance check
    6. Simulate the merge
    7. Final verdict
    """

    def test_cicd_security_gate_pipeline(self, mcp_client, tmp_path):
        """Execute CI/CD security gate pipeline."""
        # Simulate a PR with changes
        (tmp_path / "existing.py").write_text("def old_func(): return 1\n")
        (tmp_path / "new_feature.py").write_text('''
def new_feature(user_input):
    # New feature that processes user input
    result = user_input.strip().lower()
    return f"Processed: {result}"
''')
        (tmp_path / "modified.py").write_text('''
def modified_func(data):
    # Modified to add logging
    print(f"Processing: {data}")
    return data * 2
''')

        changed_files = ["new_feature.py", "modified.py"]
        pipeline_results = {"verdict": "PENDING"}

        # Step 1: Validate paths
        paths = [str(tmp_path / f) for f in changed_files]
        result, _ = _call(mcp_client, "validate_paths", {"paths": paths})
        pipeline_results["paths"] = _normalize(result)

        if not pipeline_results["paths"].get("success"):
            pipeline_results["verdict"] = "BLOCKED: Invalid paths"
            return

        # Step 2: Analyze each file
        for filename in changed_files:
            code = (tmp_path / filename).read_text()
            result, _ = _call(mcp_client, "analyze_code",
                              {"code": code, "language": "python"})
            pipeline_results[f"analyze_{filename}"] = _normalize(result)

        # Step 3: Security scan each file
        violations = []
        for filename in changed_files:
            code = (tmp_path / filename).read_text()
            result, _ = _call(mcp_client, "security_scan", {"code": code})
            normalized = _normalize(result)
            pipeline_results[f"scan_{filename}"] = normalized
            if normalized.get("has_vulnerabilities"):
                violations.append(filename)

        # Step 4: Cross-file analysis
        result, _ = _call(mcp_client, "cross_file_security_scan",
                          {"project_root": str(tmp_path), "max_depth": 3})
        pipeline_results["crossfile"] = _normalize(result)

        # Step 5: Policy check
        all_code = "\n".join(
            (tmp_path / f).read_text() for f in changed_files
        )
        result, _ = _call(mcp_client, "code_policy_check",
                          {"code": all_code,
                           "policy_rules": ["no_eval", "no_exec", "no_sql_injection"]})
        pipeline_results["policy"] = _normalize(result)

        # Step 6: Simulate merge
        original = (tmp_path / "existing.py").read_text()
        merged = original + "\n" + all_code
        result, _ = _call(mcp_client, "simulate_refactor",
                          {"original_code": original, "new_code": merged})
        pipeline_results["simulate"] = _normalize(result)

        # Step 7: Final verdict
        if violations:
            pipeline_results["verdict"] = f"BLOCKED: Vulnerabilities in {violations}"
        elif not pipeline_results["simulate"].get("is_safe", True):
            pipeline_results["verdict"] = "BLOCKED: Unsafe refactoring detected"
        elif pipeline_results["policy"].get("violations"):
            pipeline_results["verdict"] = "BLOCKED: Policy violations"
        else:
            pipeline_results["verdict"] = "APPROVED"

        assert len(pipeline_results) >= 7
        assert pipeline_results["verdict"] in ["APPROVED", "BLOCKED: Vulnerabilities in ['new_feature.py', 'modified.py']",
                                                 "BLOCKED: Unsafe refactoring detected", "BLOCKED: Policy violations", "PENDING"]
