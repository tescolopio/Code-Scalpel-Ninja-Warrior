from __future__ import annotations

import os
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_extract_code_missing_symbol_negative_control(mcp_client):
    path = _repo_root() / "torture-tests" / "stage1-qualifying-round" / "08-version-variance.py"
    result = mcp_client.tools_call(
        "extract_code",
        {"target_type": "function", "target_name": "does_not_exist_12345", "file_path": str(path)},
    )
    if isinstance(result, dict) and "error" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_extract_code_missing_file_negative_control(tmp_path, mcp_client):
    missing = tmp_path / "nope.py"
    result = mcp_client.tools_call(
        "extract_code",
        {"target_type": "function", "target_name": "x", "file_path": str(missing)},
    )
    if isinstance(result, dict) and "error" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_validate_paths_relative_paths(mcp_client):
    # validate_paths accepts both absolute and relative paths (relative to server root).
    result = mcp_client.tools_call("validate_paths", {"paths": ["README.md", "does/not/exist.txt"]})
    assert "success" in result, result
    assert result.get("success") is False, result


def test_update_symbol_invalid_syntax_fails_safely(tmp_path, mcp_client):
    demo = tmp_path / "demo.py"
    demo.write_text("def greet():\n    return 'hi'\n", encoding="utf-8")

    bad_new_code = "def greet():\n    return\n      'oops'\n"  # invalid indent

    result = mcp_client.tools_call(
        "update_symbol",
        {"file_path": str(demo), "target_type": "function", "target_name": "greet", "new_code": bad_new_code, "create_backup": True},
    )
    # update_symbol must fail safely on syntax errors.
    if isinstance(result, dict) and "error" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_update_symbol_creates_backup(tmp_path, mcp_client):
    demo = tmp_path / "demo_ok.py"
    demo.write_text("def greet():\n    return 'hi'\n", encoding="utf-8")

    new_code = "def greet():\n    return 'hello'\n"
    result = mcp_client.tools_call(
        "update_symbol",
        {"file_path": str(demo), "target_type": "function", "target_name": "greet", "new_code": new_code, "create_backup": True},
    )
    assert result.get("success") is True, result
    assert (tmp_path / "demo_ok.py.bak").exists(), result
