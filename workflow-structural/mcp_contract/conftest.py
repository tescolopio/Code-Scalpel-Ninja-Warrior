from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from .mcp_http_client import McpHttpClient, McpHttpConfig


@dataclass
class McpServerHandle:
    base_url: str
    process: subprocess.Popen[str]


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(host: str, port: int, timeout_seconds: float = 10.0) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except Exception as e:  # noqa: BLE001 - test harness utility
            last_error = e
            time.sleep(0.1)
    raise RuntimeError(f"MCP server did not start on {host}:{port}: {last_error}")


@pytest.fixture(scope="session")
def mcp_server(tmp_path_factory: pytest.TempPathFactory) -> McpServerHandle:
    """Start a real Code Scalpel MCP server in HTTP mode for contract tests."""
    repo_root = Path(__file__).resolve().parents[2]
    port = _pick_free_port()
    host = "127.0.0.1"

    log_dir = tmp_path_factory.mktemp("mcp_contract")
    log_path = log_dir / "mcp_server.log"

    env = os.environ.copy()
    # Keep output deterministic-ish.
    env.setdefault("PYTHONUNBUFFERED", "1")

    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                "code-scalpel",
                "mcp",
                "--transport",
                "streamable-http",
                "--host",
                host,
                "--port",
                str(port),
                "--root",
                str(repo_root),
            ],
            cwd=str(repo_root),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )

    _wait_for_port(host, port, timeout_seconds=15.0)

    handle = McpServerHandle(base_url=f"http://{host}:{port}", process=process)
    try:
        yield handle
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except Exception:  # noqa: BLE001
            process.kill()


@pytest.fixture()
def mcp_client(mcp_server: McpServerHandle) -> McpHttpClient:
    client = McpHttpClient(McpHttpConfig(base_url=mcp_server.base_url, timeout_seconds=10.0))
    init_resp = client.initialize()
    assert "result" in init_resp, f"initialize failed: {init_resp}"
    assert client.session_id, "initialize did not yield a session id"
    return client
