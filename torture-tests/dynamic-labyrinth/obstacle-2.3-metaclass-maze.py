"""
=============================================================================
OBSTACLE 2.3: THE METACLASS MAZE
=============================================================================

PURPOSE: Test analysis of metaclasses and dynamic class generation.
Metaclasses can dynamically create classes with arbitrary methods/attributes.
The actual class definition may exist NOWHERE in the source code.

INTENTIONAL DYNAMIC CLASS PATTERNS (DO NOT REFACTOR):

1. QueryBuilder metaclass (line 33):
   - __new__ injects find_secret() method that doesn't exist in source
   - The injected method contains SQL INJECTION vulnerability
   - Static analysis of DynamicModel class won't show this method!

2. DynamicModel class (line 43):
   - Uses QueryBuilder metaclass
   - Has find_secret() method that appears NOWHERE in class definition
   - The SQL injection is INVISIBLE without metaclass analysis

3. dynamic_class() function (line 47):
   - type() builds classes at runtime with attacker-controlled methods
   - Can inject arbitrary callable as class method
   - Class structure is entirely dynamic

4. add_method() (line 52):
   - Monkey-injects methods onto instances AFTER instantiation
   - Instance behavior differs from class definition
   - Static analysis of class is incomplete

EXPECTED BEHAVIOR (PASS):
- Recognize metaclass-generated code as potentially unanalyzable
- Flag type() calls that generate classes dynamically
- Reduce confidence for classes with metaclasses
- Detect SQL injection in metaclass-injected find_secret()
- NOT assume static class definitions are complete

FAILURE MODE (ELIMINATION):
- Analyzing only static class definition
- Missing dynamically-added methods with vulnerabilities
- Ignoring metaclass modifications entirely
=============================================================================
"""
from types import MethodType
from typing import Any, Callable


class QueryBuilder(type):
    """INTENTIONAL: Metaclass that injects vulnerable method at class creation."""
    def __new__(mcls, name, bases, attrs):
        # INTENTIONAL: Inject find_secret() - contains SQL INJECTION!
        # This method does NOT appear in DynamicModel source code
        def find_secret(self, table: str, user_input: str) -> str:
            # VULNERABILITY: SQL injection via string formatting
            return f"SELECT * FROM {table} WHERE secret = '{user_input}'"

        attrs["find_secret"] = find_secret
        return super().__new__(mcls, name, bases, attrs)


class DynamicModel(metaclass=QueryBuilder):
    """INTENTIONAL: Class with metaclass - find_secret() is injected, not defined here."""
    pass


def dynamic_class(extra: dict[str, Callable[..., Any]]):
    """INTENTIONAL: type() builds classes at runtime with attacker-controlled methods."""
    return type("DynamicClass", (DynamicModel,), extra)


def add_method(instance: Any, name: str, fn: Callable[..., Any]) -> None:
    """INTENTIONAL: Monkey-inject methods after instantiation."""
    setattr(instance, name, MethodType(fn, instance))


def example(user_input: str):
    cls = dynamic_class(
        {
            "dangerous_lookup": lambda self, payload: f"eval({payload})",
        }
    )
    obj = cls()
    add_method(obj, "tainted_call", lambda self: obj.find_secret("users", user_input))
    return obj.tainted_call()
