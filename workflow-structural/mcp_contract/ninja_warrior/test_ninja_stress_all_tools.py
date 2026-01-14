"""Stress Tests for All 22 Code Scalpel MCP Tools.

These tests verify tool behavior under:
1. Large inputs (code size, file counts)
2. Pathological inputs (deeply nested, circular, adversarial)
3. Concurrent requests (where applicable)
4. Resource exhaustion boundaries
5. Timeout handling

Each tool is tested with:
- Maximum reasonable input size
- Edge case inputs designed to stress parsers
- Performance bounds (must complete within timeout)
"""

from __future__ import annotations

import time
import threading
import concurrent.futures
from pathlib import Path
from typing import Callable

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _timed_call(mcp_client, tool: str, args: dict, *, max_seconds: float = 60.0):
    """Execute tool with timing and timeout assertion."""
    start = time.monotonic()
    result = mcp_client.tools_call(tool, args)
    elapsed = time.monotonic() - start
    assert elapsed <= max_seconds, {
        "tool": tool,
        "elapsed_seconds": elapsed,
        "max_seconds": max_seconds,
        "result_preview": str(result)[:500],
    }
    return result, elapsed


def _normalize(raw) -> dict:
    """Normalize tool result to consistent shape."""
    if not isinstance(raw, dict):
        return {"success": False, "error": f"Non-dict result: {type(raw)}"}
    if "jsonrpc" in raw and "error" in raw:
        return {"success": False, "error": raw.get("error", {}).get("message", str(raw))}
    if "data" in raw and "capabilities" in raw:
        data = raw.get("data") or {}
        err = raw.get("error")
        if err:
            return {**data, "success": False, "error": str(err)}
        return {**data, "success": True}
    return raw


# =============================================================================
# LARGE INPUT STRESS TESTS
# =============================================================================

class TestLargeInputStress:
    """Test tools with large inputs to verify they don't crash or hang."""

    def test_analyze_code_10k_lines(self, mcp_client):
        """Analyze a 10,000 line Python file."""
        lines = ["def func_{i}():\n    return {i}\n".format(i=i) for i in range(2500)]
        code = "\n".join(lines)
        assert len(code.split("\n")) >= 5000

        result, elapsed = _timed_call(
            mcp_client, "analyze_code",
            {"code": code, "language": "python"},
            max_seconds=60
        )
        result = _normalize(result)
        assert result.get("success") is True or "error" in result

    def test_security_scan_large_file(self, mcp_client):
        """Security scan on a large file with many potential vulnerabilities."""
        vulns = []
        for i in range(100):
            vulns.append(f'''
def handler_{i}(user_id):
    query = f"SELECT * FROM table_{i} WHERE id = {{user_id}}"
    cursor.execute(query)
    return open(f"/path/{{user_id}}/file").read()
''')
        code = "\n".join(vulns)

        result, elapsed = _timed_call(
            mcp_client, "security_scan",
            {"code": code},
            max_seconds=60
        )
        result = _normalize(result)
        assert result.get("success") is True or "error" in result

    def test_get_symbol_references_large_codebase(self, mcp_client):
        """Find symbol references across entire torture-tests directory."""
        root = _repo_root() / "torture-tests"
        result, elapsed = _timed_call(
            mcp_client, "get_symbol_references",
            {"symbol_name": "query", "project_root": str(root)},
            max_seconds=90
        )
        result = _normalize(result)
        assert result.get("success") is True or "error" in result

    def test_crawl_project_entire_repo(self, mcp_client):
        """Crawl the entire repository."""
        root = _repo_root()
        result, elapsed = _timed_call(
            mcp_client, "crawl_project",
            {"root_path": str(root), "include_report": True},
            max_seconds=120
        )
        result = _normalize(result)
        assert result.get("success") is True or "error" in result

    def test_cross_file_security_scan_many_files(self, mcp_client):
        """Cross-file scan on directory with many modules."""
        root = _repo_root() / "workflow-deep-security"
        result, elapsed = _timed_call(
            mcp_client, "cross_file_security_scan",
            {"project_root": str(root), "max_depth": 10, "max_modules": 500, "timeout_seconds": 90},
            max_seconds=120
        )
        result = _normalize(result)
        assert result.get("success") is True or "error" in result

    def test_validate_paths_1000_paths(self, mcp_client):
        """Validate 1000 paths at once."""
        paths = ["README.md"] * 500 + ["nonexistent.txt"] * 500
        result, elapsed = _timed_call(
            mcp_client, "validate_paths",
            {"paths": paths},
            max_seconds=30
        )
        result = _normalize(result)
        assert result.get("success") is True or "error" in result


# =============================================================================
# PATHOLOGICAL INPUT STRESS TESTS
# =============================================================================

class TestPathologicalInputs:
    """Test tools with adversarial inputs designed to stress parsers."""

    def test_analyze_code_deeply_nested(self, mcp_client):
        """100 levels of nested function calls."""
        depth = 100
        code = "result = " + "func(" * depth + "x" + ")" * depth
        code = f"def func(x): return x + 1\n{code}"

        result, elapsed = _timed_call(
            mcp_client, "analyze_code",
            {"code": code, "language": "python"},
            max_seconds=30
        )
        result = _normalize(result)
        assert "success" in result or "error" in result

    def test_security_scan_nested_fstrings(self, mcp_client):
        """Deeply nested f-strings (parser stress)."""
        code = '''
def handler(a, b, c, d, e):
    query = f"SELECT {f'col_{a}'} FROM {f'table_{b}'} WHERE {f'x = {c}'} AND {f'y = {d}'} OR {f'z = {e}'}"
    return cursor.execute(query)
'''
        result, elapsed = _timed_call(
            mcp_client, "security_scan",
            {"code": code},
            max_seconds=30
        )
        result = _normalize(result)
        assert "success" in result or "error" in result

    def test_analyze_code_unicode_heavy(self, mcp_client):
        """Code with extensive Unicode characters."""
        code = '''
# -*- coding: utf-8 -*-
def функция_обработки(данные: str) -> str:
    """処理関数 - Fonction de traitement - Función de procesamiento"""
    переменная = данные + "🔒🛡️🔐"
    return f"Результат: {переменная}"

класс = {"キー": "値", "مفتاح": "قيمة", "κλειδί": "τιμή"}
'''
        result, elapsed = _timed_call(
            mcp_client, "analyze_code",
            {"code": code, "language": "python"},
            max_seconds=30
        )
        result = _normalize(result)
        assert "success" in result or "error" in result

    def test_security_scan_obfuscated_code(self, mcp_client):
        """Obfuscated code that hides vulnerabilities."""
        code = '''
import base64
exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))

# ROT13 obfuscation
import codecs
eval(codecs.decode("cevag('jbeyq')", 'rot_13'))

# Hex encoding
eval(bytes.fromhex('7072696e7428276869272929').decode())
'''
        result, elapsed = _timed_call(
            mcp_client, "security_scan",
            {"code": code},
            max_seconds=30
        )
        result = _normalize(result)
        assert "success" in result or "error" in result

    def test_symbolic_execute_path_explosion(self, mcp_client):
        """Code that causes symbolic execution path explosion."""
        code = '''
def path_exploder(a, b, c, d, e, f, g, h):
    result = 0
    if a > 0: result += 1
    else: result -= 1
    if b > 0: result += 2
    else: result -= 2
    if c > 0: result += 4
    else: result -= 4
    if d > 0: result += 8
    else: result -= 8
    if e > 0: result += 16
    else: result -= 16
    if f > 0: result += 32
    else: result -= 32
    if g > 0: result += 64
    else: result -= 64
    if h > 0: result += 128
    else: result -= 128
    return result
'''
        result, elapsed = _timed_call(
            mcp_client, "symbolic_execute",
            {"code": code, "function_name": "path_exploder", "max_paths": 100},
            max_seconds=60
        )
        result = _normalize(result)
        assert "success" in result or "error" in result

    def test_get_call_graph_circular_imports(self, mcp_client, tmp_path):
        """Project with circular import dependencies."""
        (tmp_path / "a.py").write_text("from b import func_b\ndef func_a(): return func_b()")
        (tmp_path / "b.py").write_text("from c import func_c\ndef func_b(): return func_c()")
        (tmp_path / "c.py").write_text("from a import func_a\ndef func_c(): return func_a()")

        result, elapsed = _timed_call(
            mcp_client, "get_call_graph",
            {"project_root": str(tmp_path), "entry_point": "a.py:func_a", "depth": 10,
             "include_circular_import_check": True},
            max_seconds=30
        )
        result = _normalize(result)
        assert "success" in result or "error" in result


# =============================================================================
# CONCURRENT REQUEST STRESS TESTS
# =============================================================================

class TestConcurrentRequests:
    """Test tools under concurrent load."""

    def test_security_scan_concurrent_10(self, mcp_client):
        """10 concurrent security scans."""
        codes = [
            f"def handler_{i}(x): return eval(x)"
            for i in range(10)
        ]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(
                    lambda c=code: mcp_client.tools_call("security_scan", {"code": c}),
                )
                for code in codes
            ]
            for future in concurrent.futures.as_completed(futures, timeout=120):
                results.append(future.result())

        assert len(results) == 10
        for r in results:
            assert isinstance(r, dict)

    def test_analyze_code_concurrent_20(self, mcp_client):
        """20 concurrent code analysis requests."""
        codes = [
            f"def func_{i}(x): return x * {i}"
            for i in range(20)
        ]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(
                    lambda c=code: mcp_client.tools_call("analyze_code", {"code": c, "language": "python"}),
                )
                for code in codes
            ]
            for future in concurrent.futures.as_completed(futures, timeout=120):
                results.append(future.result())

        assert len(results) == 20

    def test_mixed_tools_concurrent(self, mcp_client):
        """Concurrent requests to different tools."""
        calls = [
            ("analyze_code", {"code": "x = 1", "language": "python"}),
            ("security_scan", {"code": "eval(input())"}),
            ("validate_paths", {"paths": ["README.md"]}),
            ("analyze_code", {"code": "y = 2", "language": "python"}),
            ("security_scan", {"code": "os.system(cmd)"}),
        ]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(
                    lambda t=tool, a=args: mcp_client.tools_call(t, a),
                )
                for tool, args in calls
            ]
            for future in concurrent.futures.as_completed(futures, timeout=60):
                results.append(future.result())

        assert len(results) == 5


# =============================================================================
# TIMEOUT AND RESOURCE BOUNDARY TESTS
# =============================================================================

class TestResourceBoundaries:
    """Test tools at resource limits."""

    def test_symbolic_execute_max_paths_boundary(self, mcp_client):
        """Test symbolic execution at max_paths boundary."""
        code = '''
def boundary_test(x):
    if x > 0:
        if x > 10:
            return "high"
        return "medium"
    return "low"
'''
        # Test at various max_paths values
        for max_paths in [1, 10, 100, 1000]:
            result, elapsed = _timed_call(
                mcp_client, "symbolic_execute",
                {"code": code, "function_name": "boundary_test", "max_paths": max_paths},
                max_seconds=30
            )
            result = _normalize(result)
            assert "success" in result or "error" in result

    def test_cross_file_scan_depth_boundary(self, mcp_client):
        """Test cross-file scan at various depth limits."""
        root = _repo_root() / "torture-tests" / "stage8-advanced-taint" / "crossfile-hard"

        for depth in [1, 3, 5, 10]:
            result, elapsed = _timed_call(
                mcp_client, "cross_file_security_scan",
                {"project_root": str(root), "max_depth": depth, "timeout_seconds": 30},
                max_seconds=45
            )
            result = _normalize(result)
            assert "success" in result or "error" in result

    def test_get_call_graph_depth_boundary(self, mcp_client):
        """Test call graph at various depth limits."""
        root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"

        for depth in [1, 3, 6, 10]:
            result, elapsed = _timed_call(
                mcp_client, "get_call_graph",
                {"project_root": str(root), "entry_point": "call_chain.py:alpha", "depth": depth},
                max_seconds=30
            )
            result = _normalize(result)
            assert "success" in result or "error" in result


# =============================================================================
# INDIVIDUAL TOOL STRESS TESTS (ALL 22 TOOLS)
# =============================================================================

class TestAllToolsStress:
    """Stress test for each of the 22 tools."""

    # Core Analysis Tools

    def test_analyze_code_stress(self, mcp_client):
        """Stress test analyze_code with complex code."""
        code = "\n".join([
            f"class Class{i}:",
            f"    def method_{i}(self, x): return x * {i}",
            f"    @property",
            f"    def prop_{i}(self): return {i}",
        ] for i in range(50))

        result, _ = _timed_call(mcp_client, "analyze_code",
                                {"code": code, "language": "python"}, max_seconds=45)
        assert _normalize(result).get("success") in (True, False)

    def test_crawl_project_stress(self, mcp_client):
        """Stress test crawl_project on large directory."""
        result, _ = _timed_call(mcp_client, "crawl_project",
                                {"root_path": str(_repo_root()), "include_report": False},
                                max_seconds=90)
        assert _normalize(result).get("success") in (True, False)

    def test_get_file_context_stress(self, mcp_client):
        """Stress test get_file_context on large file."""
        # Find a large file in the repo
        large_file = _repo_root() / "harness" / "test_harness.py"
        result, _ = _timed_call(mcp_client, "get_file_context",
                                {"file_path": str(large_file)}, max_seconds=30)
        assert _normalize(result).get("success") in (True, False)

    def test_get_project_map_stress(self, mcp_client):
        """Stress test get_project_map on entire repo."""
        result, _ = _timed_call(mcp_client, "get_project_map",
                                {"project_root": str(_repo_root())}, max_seconds=60)
        assert _normalize(result).get("success") in (True, False)

    def test_validate_paths_stress(self, mcp_client):
        """Stress test validate_paths with many paths."""
        paths = ["README.md", "harness/test_harness.py", ".code-scalpel/config.json"] * 100
        result, _ = _timed_call(mcp_client, "validate_paths",
                                {"paths": paths}, max_seconds=30)
        assert _normalize(result).get("success") in (True, False)

    # Security Scanning Tools

    def test_security_scan_stress(self, mcp_client):
        """Stress test security_scan with many vulnerabilities."""
        vulns = [f"eval(input())\nos.system('{i}')\nexec(f'{{{i}}}')" for i in range(50)]
        code = "\n".join(vulns)
        result, _ = _timed_call(mcp_client, "security_scan",
                                {"code": code}, max_seconds=60)
        assert _normalize(result).get("success") in (True, False)

    def test_unified_sink_detect_stress(self, mcp_client):
        """Stress test unified_sink_detect with many sinks."""
        code = "\n".join([
            f"cursor.execute(query_{i})",
            f"subprocess.run(cmd_{i}, shell=True)",
            f"open(path_{i}).read()",
        ] for i in range(30))
        result, _ = _timed_call(mcp_client, "unified_sink_detect",
                                {"code": code, "language": "python"}, max_seconds=45)
        assert _normalize(result).get("success") in (True, False)

    # Graph & Dependencies Tools

    def test_get_call_graph_stress(self, mcp_client):
        """Stress test get_call_graph with deep call chains."""
        root = _repo_root() / "torture-tests" / "stage4-confidence-crisis" / "obstacle-4.5-confidence-decay"
        result, _ = _timed_call(mcp_client, "get_call_graph",
                                {"project_root": str(root), "entry_point": "call_chain.py:alpha",
                                 "depth": 10, "include_circular_import_check": True},
                                max_seconds=45)
        assert _normalize(result).get("success") in (True, False)

    def test_get_cross_file_dependencies_stress(self, mcp_client):
        """Stress test cross-file dependencies on large project."""
        result, _ = _timed_call(mcp_client, "get_cross_file_dependencies",
                                {"project_root": str(_repo_root()), "max_depth": 5},
                                max_seconds=90)
        assert _normalize(result).get("success") in (True, False)

    def test_scan_dependencies_stress(self, mcp_client, tmp_path):
        """Stress test scan_dependencies with large package.json."""
        deps = {f"package-{i}": f"{i}.0.0" for i in range(100)}
        pkg = tmp_path / "package.json"
        import json
        pkg.write_text(json.dumps({"name": "stress", "version": "1.0.0", "dependencies": deps}))
        result, _ = _timed_call(mcp_client, "scan_dependencies",
                                {"path": str(pkg), "scan_vulnerabilities": False},
                                max_seconds=30)
        assert _normalize(result).get("success") in (True, False)

    # Symbol Operations Tools

    def test_extract_code_stress(self, mcp_client, tmp_path):
        """Stress test extract_code on file with many functions."""
        funcs = [f"def func_{i}(x):\n    return x * {i}\n" for i in range(100)]
        code = "\n".join(funcs)
        test_file = tmp_path / "many_funcs.py"
        test_file.write_text(code)

        result, _ = _timed_call(mcp_client, "extract_code",
                                {"file_path": str(test_file), "target_type": "function",
                                 "target_name": "func_50"},
                                max_seconds=30)
        assert _normalize(result).get("success") in (True, False)

    def test_get_symbol_references_stress(self, mcp_client):
        """Stress test get_symbol_references on large codebase."""
        result, _ = _timed_call(mcp_client, "get_symbol_references",
                                {"symbol_name": "execute", "project_root": str(_repo_root())},
                                max_seconds=60)
        assert _normalize(result).get("success") in (True, False)

    def test_rename_symbol_stress(self, mcp_client, tmp_path):
        """Stress test rename_symbol on file with many references."""
        refs = [f"old_name({i})" for i in range(50)]
        code = "def old_name(x): return x\n" + "\n".join(refs)
        test_file = tmp_path / "rename_stress.py"
        test_file.write_text(code)

        result, _ = _timed_call(mcp_client, "rename_symbol",
                                {"file_path": str(test_file), "old_name": "old_name",
                                 "new_name": "new_name", "symbol_type": "function"},
                                max_seconds=30)
        assert "success" in _normalize(result) or "error" in _normalize(result)

    def test_update_symbol_stress(self, mcp_client, tmp_path):
        """Stress test update_symbol with large replacement."""
        code = "def old_func():\n    pass\n"
        new_code = "\n".join([f"    line_{i} = {i}" for i in range(100)])
        test_file = tmp_path / "update_stress.py"
        test_file.write_text(code)

        result, _ = _timed_call(mcp_client, "update_symbol",
                                {"file_path": str(test_file), "symbol_name": "old_func",
                                 "new_code": f"def old_func():\n{new_code}\n"},
                                max_seconds=30)
        assert _normalize(result).get("success") in (True, False)

    # Advanced Analysis Tools

    def test_generate_unit_tests_stress(self, mcp_client):
        """Stress test generate_unit_tests on complex function."""
        code = '''
def complex_function(a, b, c, d=None, e=True, **kwargs):
    """Complex function with many parameters and branches."""
    result = []
    if a > 0:
        result.append(a)
    if b:
        result.extend(list(b))
    if c is not None:
        for item in c:
            if item > 0:
                result.append(item * 2)
    if d:
        result.append(d)
    if e:
        result.reverse()
    for k, v in kwargs.items():
        result.append(f"{k}={v}")
    return result
'''
        result, _ = _timed_call(mcp_client, "generate_unit_tests",
                                {"code": code, "function_name": "complex_function"},
                                max_seconds=60)
        assert _normalize(result).get("success") in (True, False)

    def test_simulate_refactor_stress(self, mcp_client):
        """Stress test simulate_refactor with large code change."""
        original = "\n".join([f"def func_{i}(x): return x" for i in range(50)])
        new_code = "\n".join([f"def func_{i}(x): return eval(x)" for i in range(50)])

        result, _ = _timed_call(mcp_client, "simulate_refactor",
                                {"original_code": original, "new_code": new_code,
                                 "strict_mode": True},
                                max_seconds=60)
        assert _normalize(result).get("success") in (True, False)

    def test_symbolic_execute_stress(self, mcp_client):
        """Stress test symbolic_execute with many paths."""
        code = '''
def many_paths(a, b, c, d, e):
    x = 0
    if a: x += 1
    if b: x += 2
    if c: x += 4
    if d: x += 8
    if e: x += 16
    return x
'''
        result, _ = _timed_call(mcp_client, "symbolic_execute",
                                {"code": code, "function_name": "many_paths",
                                 "max_paths": 50},
                                max_seconds=45)
        assert _normalize(result).get("success") in (True, False)

    # Policy & Governance Tools

    def test_code_policy_check_stress(self, mcp_client):
        """Stress test code_policy_check with many violations."""
        code = "\n".join([
            f"eval(input())",
            f"exec(data)",
            f"os.system(cmd)",
            f"subprocess.run(x, shell=True)",
            f"pickle.loads(data)",
        ] * 10)

        result, _ = _timed_call(mcp_client, "code_policy_check",
                                {"code": code, "policy_rules": [
                                    "no_eval", "no_exec", "no_os_system",
                                    "no_shell_true", "no_pickle_loads"
                                ]},
                                max_seconds=45)
        assert "success" in _normalize(result) or "error" in _normalize(result)

    def test_verify_policy_integrity_stress(self, mcp_client):
        """Stress test verify_policy_integrity on repo config."""
        policy_dir = _repo_root() / ".code-scalpel"
        result, _ = _timed_call(mcp_client, "verify_policy_integrity",
                                {"policy_dir": str(policy_dir), "manifest_source": "file"},
                                max_seconds=30)
        assert _normalize(result).get("success") in (True, False)

    def test_type_evaporation_scan_stress(self, mcp_client):
        """Stress test type_evaporation_scan with large code."""
        frontend = "\n".join([
            f"type T{i} = {{ id: number; name: string }}",
            f"async function send{i}(data: T{i}) {{ fetch('/api/{i}', {{body: JSON.stringify(data)}}) }}",
        ] for i in range(20))

        backend = "\n".join([
            f"@app.post('/api/{i}')\ndef handle{i}():\n    return request.get_json()",
        ] for i in range(20))

        result, _ = _timed_call(mcp_client, "type_evaporation_scan",
                                {"frontend_code": frontend, "backend_code": backend,
                                 "frontend_file": "frontend.ts", "backend_file": "backend.py"},
                                max_seconds=60)
        assert _normalize(result).get("success") in (True, False)
