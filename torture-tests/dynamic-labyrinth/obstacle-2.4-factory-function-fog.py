"""
=============================================================================
OBSTACLE 2.4: THE FACTORY FUNCTION FOG
=============================================================================

PURPOSE: Test analysis of factory functions and closures that generate code.
Factories return functions/classes that didn't exist in source. Generated code
captures variables from enclosing scope - difficult to analyze statically.

INTENTIONAL FACTORY/CLOSURE PATTERNS (DO NOT REFACTOR):

1. handler_factory() (line 35):
   - Returns function that captures table_name in closure
   - Attacker can choose table_name at runtime
   - Generated handler has SQL INJECTION vulnerability
   - The captured_table value flows into SQL query

2. decorator_injector() (line 46):
   - Returns decorator that wraps functions
   - Captured transform modifies tainted values
   - Decorator transformations must be tracked

3. compose_pipeline() (line 60):
   - Higher-order function composition
   - Hides vulnerability in middle step
   - Taint flows: user_table -> handler_factory -> handler -> render

EXPECTED BEHAVIOR (PASS):
- Track closure variable capture
- Factory-generated functions inherit taint from inputs
- Analyze decorator transformations
- Track taint through higher-order functions
- Acknowledge increased uncertainty for complex patterns

FAILURE MODE (ELIMINATION):
- Losing track of taint when it enters a factory
- Treating generated functions as independent of inputs
- Ignoring closure capture
- Missing SQL injection in factory-generated handler
=============================================================================
"""
from functools import wraps
from typing import Callable


def handler_factory(table_name: str) -> Callable[[str], str]:
    """INTENTIONAL: Factory generates handler with captured tainted value."""
    captured_table = table_name  # INTENTIONAL: Attacker can choose at runtime

    def handler(user_input: str) -> str:
        # VULNERABILITY: SQL injection - both captured_table and user_input tainted
        return f"SELECT * FROM {captured_table} WHERE id = {user_input}"

    return handler


def decorator_injector(transform: Callable[[str], str]):
    """INTENTIONAL: Decorator captures transform function in closure."""
    def decorate(fn: Callable[[str], str]):
        @wraps(fn)
        def wrapper(user_value: str) -> str:
            # INTENTIONAL: Captured transform modifies the tainted value
            mutated = transform(user_value)
            return fn(mutated)

        return wrapper

    return decorate

@decorator_injector(lambda raw: raw.replace("'", ""))
def render(template: str) -> str:
    return template


def compose_pipeline(user_table: str, user_input: str):
    """Higher-order function composition hides the vulnerable middle step."""
    handler = handler_factory(user_table)
    payload = handler(user_input)
    return render(payload)
