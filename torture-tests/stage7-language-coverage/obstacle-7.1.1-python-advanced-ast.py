"""
###############################################################################
#     STAGE 7.1.1: PYTHON ADVANCED AST COVERAGE                                #
#     Requirement: 100% Python AST node support                                #
###############################################################################

PURPOSE: Test parsing and analysis of Python 3.8+ advanced features including
walrus operator, match/case statements, async generators, and complex expressions.

SUCCESS CRITERIA:
- Parse all Python 3.8-3.12 syntax without errors
- Extract all functions/classes correctly
- Calculate complexity accurately
- Detect security issues in modern syntax

COVERAGE REQUIREMENTS:
✅ Walrus operator (:=) in various contexts
✅ Structural pattern matching (match/case)
✅ Async generators and comprehensions
✅ Positional-only and keyword-only parameters
✅ Union types (|) and Optional types
✅ Nested f-strings with expressions
✅ Assignment expressions in complex contexts
"""

import asyncio
from typing import Optional, Union
from collections.abc import AsyncGenerator


# ============================================================================
# WALRUS OPERATOR COVERAGE
# ============================================================================

def walrus_in_if(data: list[str]) -> Optional[str]:
    """Walrus operator in if statement condition."""
    if (match := next((x for x in data if x.startswith("admin")), None)):
        return f"Found: {match}"
    return None


def walrus_in_while() -> list[int]:
    """Walrus operator in while loop."""
    results = []
    while (chunk := input("Enter number (or 'done'): ")) != "done":
        results.append(int(chunk))
    return results


def walrus_in_comprehension(items: list[str]) -> list[tuple[str, int]]:
    """Walrus operator in list comprehension."""
    return [(item, length) for item in items if (length := len(item)) > 5]


# ============================================================================
# STRUCTURAL PATTERN MATCHING (Python 3.10+)
# ============================================================================

def match_case_router(command: dict) -> str:
    """Pattern matching with multiple patterns."""
    match command:
        case {"action": "get", "id": user_id}:
            # SECURITY: Potential SQL injection if user_id not validated
            return f"SELECT * FROM users WHERE id = {user_id}"
        
        case {"action": "delete", "id": user_id, "confirm": True}:
            # SECURITY: Potential SQL injection
            return f"DELETE FROM users WHERE id = {user_id}"
        
        case {"action": "search", "query": query_str}:
            # SECURITY: Potential SQL injection in search query
            return f"SELECT * FROM users WHERE name LIKE '%{query_str}%'"
        
        case {"action": "batch", "ids": [*ids]}:
            # SECURITY: Potential SQL injection with multiple IDs
            id_list = ",".join(str(i) for i in ids)
            return f"SELECT * FROM users WHERE id IN ({id_list})"
        
        case _:
            return "Unknown command"


# ============================================================================
# ASYNC GENERATORS AND COMPREHENSIONS
# ============================================================================

async def async_generator_source() -> AsyncGenerator[str, None]:
    """Async generator that yields sensitive data."""
    # SECURITY: Async generator yielding passwords
    passwords = ["admin123", "password", "secret"]
    for pwd in passwords:
        await asyncio.sleep(0.1)
        yield pwd


async def async_comprehension_leak() -> list[str]:
    """Async comprehension with potential data leak."""
    # SECURITY: Collecting sensitive data in async comprehension
    sensitive = [item async for item in async_generator_source()]
    
    # SECURITY: Logging sensitive data
    print(f"Collected: {sensitive}")
    return sensitive


# ============================================================================
# POSITIONAL-ONLY AND KEYWORD-ONLY PARAMETERS
# ============================================================================

def strict_parameters(
    username: str,           # Regular parameter
    /,                       # Everything before is positional-only
    password: str,           # Can be positional or keyword
    *,                       # Everything after is keyword-only
    require_2fa: bool = False,
    admin: bool = False
) -> str:
    """Function with positional-only and keyword-only parameters."""
    # SECURITY: SQL injection via username
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    if admin:
        # SECURITY: Privilege escalation if admin flag can be manipulated
        query += " AND role = 'admin'"
    
    return query


# ============================================================================
# UNION TYPES AND MODERN TYPE ANNOTATIONS
# ============================================================================

def union_type_parameter(value: str | int | None) -> str:
    """Using | for union types (Python 3.10+)."""
    match value:
        case str(s):
            # SECURITY: XSS if used in HTML without escaping
            return f"<div>String: {s}</div>"
        case int(i):
            return f"<div>Integer: {i}</div>"
        case None:
            return "<div>No value</div>"


def optional_modern(config: dict[str, str | int] | None = None) -> str:
    """Modern optional syntax with dict."""
    if config is None:
        return "Default config"
    
    # SECURITY: Command injection if config values come from user input
    command = f"process --name {config.get('name', 'default')}"
    return command


# ============================================================================
# NESTED F-STRINGS WITH COMPLEX EXPRESSIONS
# ============================================================================

def nested_fstring_complexity(user: dict, items: list[dict]) -> str:
    """Nested f-strings with complex expressions."""
    # SECURITY: Multiple injection points in nested f-strings
    result = f"""
    User: {user['name']}
    Items: {', '.join(f"{item['name']} (${item['price']:.2f})" for item in items)}
    Total: ${sum(item['price'] for item in items):.2f}
    """
    
    # SECURITY: Inserting user-controlled data into HTML
    return f"<div>{result}</div>"


# ============================================================================
# ASSIGNMENT EXPRESSIONS IN COMPLEX CONTEXTS
# ============================================================================

def assignment_expr_chain(data: list[dict]) -> list[str]:
    """Multiple walrus operators in complex expression."""
    # SECURITY: Multiple potential injection points
    return [
        f"User {user['id']}: {summary}"
        for user in data
        if (summary := f"{user['name']} - {user['email']}") and
           (is_admin := user.get('role') == 'admin') and
           is_admin
    ]


# ============================================================================
# EDGE CASE: COMPLEX ASYNC CONTEXT MANAGER
# ============================================================================

class AsyncDatabaseConnection:
    """Async context manager for database operations."""
    
    async def __aenter__(self):
        # SECURITY: Connection string might contain secrets
        print("Connecting to database")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        print("Closing database connection")
    
    async def execute(self, query: str) -> list:
        """Execute SQL query."""
        # SECURITY: SQL injection vulnerability
        await asyncio.sleep(0.1)
        return [{"result": query}]


async def async_context_usage(user_input: str):
    """Using async context manager with user input."""
    async with AsyncDatabaseConnection() as db:
        # SECURITY: SQL injection via user_input
        results = await db.execute(f"SELECT * FROM data WHERE id = {user_input}")
        return results


# ============================================================================
# TEST EXPECTATIONS
# ============================================================================

"""
EXPECTED DETECTION (Security Scan):
1. SQL injection in match_case_router (4 cases) - Lines ~46, 50, 54, 59
2. Password exposure in async_generator_source - Line 73
3. Sensitive data logging in async_comprehension_leak - Line 79
4. SQL injection in strict_parameters - Line 97
5. Privilege escalation in strict_parameters - Line 102
6. XSS in union_type_parameter - Line 117, 119
7. Command injection in optional_modern - Line 131
8. HTML injection in nested_fstring_complexity - Line 146
9. SQL injection in AsyncDatabaseConnection.execute - Line 169
10. SQL injection in async_context_usage - Line 176

EXPECTED PARSING (Analyze Code):
- All functions should be detected: 11 functions + 1 class
- Complexity should account for match/case branches
- Async functions should be identified
- Type annotations should be parsed

PASS CRITERIA:
✅ File parses without syntax errors
✅ All 11 functions and 1 class extracted
✅ At least 8/10 security issues detected
✅ No false positives on valid Python 3.10+ syntax
"""
