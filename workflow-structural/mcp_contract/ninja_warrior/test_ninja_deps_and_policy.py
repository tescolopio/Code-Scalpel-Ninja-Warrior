from __future__ import annotations

import os
import time
from pathlib import Path

import pytest


def test_scan_dependencies_invalid_path_negative_control(mcp_client, tmp_path):
    missing = tmp_path / "nope.requirements.txt"
    result = mcp_client.tools_call("scan_dependencies", {"path": str(missing), "scan_vulnerabilities": False, "include_dev": False})
    if isinstance(result, dict) and "error" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_scan_dependencies_requirements_no_network(mcp_client, tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")

    start = time.monotonic()
    result = mcp_client.tools_call("scan_dependencies", {"path": str(req), "scan_vulnerabilities": False, "include_dev": False})
    elapsed = time.monotonic() - start
    assert elapsed <= 15, {"elapsed": elapsed, "result": result}

    assert result.get("success") is True, result
    assert result.get("total_dependencies", 0) >= 1, result


def test_verify_policy_integrity_fail_closed_without_secret(mcp_client):
    # Must fail closed when secret is missing.
    os.environ.pop("SCALPEL_MANIFEST_SECRET", None)
    result = mcp_client.tools_call("verify_policy_integrity", {"policy_dir": ".code-scalpel", "manifest_source": "file"})
    # Depending on runtime, may return {success:false,error:...} or JSON-RPC error wrapper.
    if isinstance(result, dict) and "error" in result and "jsonrpc" in result:
        assert result["error"], result
    else:
        assert result.get("success") is False, result


def test_type_evaporation_scan_safe_control_has_zero_cross_file_issues(mcp_client):
    frontend = """
export async function sendRole(role: string) {
  return fetch('/api/boundary/role', { method: 'POST', body: JSON.stringify({ role }) })
}
""".strip()

    backend = """
from flask import Flask, request
app = Flask(__name__)

@app.post('/api/boundary/role')
def role():
    data = request.get_json(force=True)
    role = data.get('role')
    if role not in ('admin', 'user'):
        return {'error': 'invalid'}, 400
    return {'role': role}
""".strip()

    result = mcp_client.tools_call(
        "type_evaporation_scan",
        {"frontend_code": frontend, "backend_code": backend, "frontend_file": "frontend.ts", "backend_file": "backend.py"},
    )
    assert result.get("success") is True, result
    assert result.get("cross_file_issues") == 0, result
