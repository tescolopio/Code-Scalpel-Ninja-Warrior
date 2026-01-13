from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

import os


@dataclass
class McpHttpConfig:
    base_url: str
    timeout_seconds: float = 10.0


class McpHttpClient:
    """Minimal MCP-over-HTTP client for Code Scalpel's SSE transport.

    Code Scalpel's HTTP MCP endpoint responds with `text/event-stream` and
    embeds JSON-RPC responses in `data: ...` lines.

    This client is deliberately small and stdlib-only.
    """

    def __init__(self, config: McpHttpConfig):
        self._config = config
        self._session_id: Optional[str] = None
        self._next_id = 1
        # Some tools legitimately take longer than a default socket timeout.
        # Keep this configurable so contract tests can run in slower CI.
        self._timeout_seconds = float(os.environ.get("MCP_HTTP_TIMEOUT_SECONDS", "120"))

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    def initialize(self) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": self._alloc_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "code-scalpel-ninja-warrior-contract", "version": "0"},
            },
        }
        resp_json, headers = self._post_and_read_first_jsonrpc(payload, session_id=None)
        session_id = headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        return resp_json

    def tools_list(self) -> dict[str, Any]:
        self._require_session()
        payload = {"jsonrpc": "2.0", "id": self._alloc_id(), "method": "tools/list", "params": {}}
        resp_json, _ = self._post_and_read_first_jsonrpc(payload, session_id=self._session_id)
        return resp_json

    def tools_call(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool and return a best-effort parsed result.

        The MCP spec returns a wrapper result with `content`. Code Scalpel often
        returns tool outputs as JSON inside `content[0].text`.
        """
        self._require_session()
        payload = {
            "jsonrpc": "2.0",
            "id": self._alloc_id(),
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        resp_json, _ = self._post_and_read_first_jsonrpc(payload, session_id=self._session_id)
        # Unwrap JSON-RPC envelope
        if "error" in resp_json:
            return resp_json
        result = resp_json.get("result")
        if result is None:
            return resp_json

        # Some servers return the tool result directly.
        if isinstance(result, dict) and ("success" in result or "has_vulnerabilities" in result):
            return result

        # MCP wrapper: { content: [{type:'text', text:'...'}], isError: bool }
        if isinstance(result, dict) and "content" in result:
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    text = first["text"].strip()
                    # If the tool returns JSON-in-text, parse it.
                    if text.startswith("{") or text.startswith("["):
                        try:
                            return json.loads(text)
                        except Exception:
                            return {"_raw_text": text, "_mcp": result}
                    return {"_raw_text": text, "_mcp": result}

        return result

    def _alloc_id(self) -> int:
        value = self._next_id
        self._next_id += 1
        return value

    def _require_session(self) -> None:
        if not self._session_id:
            raise RuntimeError("MCP session not initialized (call initialize() first)")

    def _post_and_read_first_jsonrpc(self, payload: dict[str, Any], session_id: Optional[str]) -> tuple[dict[str, Any], dict[str, str]]:
        """POST JSON-RPC and parse the first `data: {jsonrpc...}` SSE message."""
        url = self._config.base_url.rstrip("/") + "/mcp"
        body = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Cache-Control": "no-cache",
        }
        if session_id:
            headers["mcp-session-id"] = session_id

        request = urllib.request.Request(url=url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(request, timeout=max(self._config.timeout_seconds, self._timeout_seconds)) as resp:
                resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                # Read SSE stream line-by-line until we see a data: line.
                # Use the larger of the configured test timeout and the env override.
                effective_timeout = max(self._config.timeout_seconds, self._timeout_seconds)
                deadline = time.time() + effective_timeout
                while time.time() < deadline:
                    line = resp.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith(b"data:"):
                        raw = line[len(b"data:") :].strip().decode("utf-8", errors="replace")
                        return json.loads(raw), resp_headers
                raise TimeoutError("Timed out waiting for SSE data: line")
        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode("utf-8", errors="replace")
                return {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": e.code, "message": error_body}}, {}
            except Exception:
                return {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": e.code, "message": str(e)}}, {}
