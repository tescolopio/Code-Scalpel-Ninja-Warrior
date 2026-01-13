from __future__ import annotations

import time
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_get_symbol_references_found(mcp_client):
    root = _repo_root() / "torture-tests"
    result = mcp_client.tools_call("get_symbol_references", {"symbol_name": "search_users", "project_root": str(root)})
    assert result.get("success") is True, result
    assert isinstance(result.get("references"), list), result


def test_get_symbol_references_missing_symbol_negative_control(mcp_client):
    root = _repo_root() / "torture-tests"
    result = mcp_client.tools_call("get_symbol_references", {"symbol_name": "definitely_not_a_real_symbol_12345", "project_root": str(root)})
    # Accept either (success True with 0 refs) or (success False with error) depending on implementation.
    assert "success" in result, result
    if result.get("success") is True:
        assert result.get("total_references") in (0, None) or result.get("total_references", 0) == 0, result


def test_get_file_context_unsupported_extension_negative_control(mcp_client, tmp_path):
    weird = tmp_path / "data.bin"
    weird.write_bytes(b"\x00\x01\x02\x03")

    result = mcp_client.tools_call("get_file_context", {"file_path": str(weird)})
    if isinstance(result, dict) and "error" in result and "jsonrpc" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_get_file_context_large_file_bounded(mcp_client, tmp_path):
    big = tmp_path / "big.py"
    big.write_text("\n".join(["def f%d():\n    return %d" % (i, i) for i in range(200)]), encoding="utf-8")

    start = time.monotonic()
    result = mcp_client.tools_call("get_file_context", {"file_path": str(big)})
    elapsed = time.monotonic() - start
    assert elapsed <= 20, {"elapsed": elapsed, "result": result}

    assert result.get("success") is True, result
    assert len(result.get("functions") or []) >= 100, result
