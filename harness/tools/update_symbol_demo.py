"""Small, isolated fixture for demonstrating mcp_code-scalpel_update_symbol.

This file is intentionally simple so we can safely replace symbols without
impacting the benchmark fixtures.
"""


def greet(name: str) -> str:
    name = name.strip()
    if not name:
        return "hello"
    return f"hello {name}"
