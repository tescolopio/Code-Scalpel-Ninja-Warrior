"""
Metaclasses and dynamic class generation that inject security-relevant logic.
Expected: Analysis should flag dynamically added methods and reduce confidence.
"""
from types import MethodType
from typing import Any, Callable


class QueryBuilder(type):
    def __new__(mcls, name, bases, attrs):
        # Inject a query method that did not exist in source.
        def find_secret(self, table: str, user_input: str) -> str:
            return f"SELECT * FROM {table} WHERE secret = '{user_input}'"

        attrs["find_secret"] = find_secret
        return super().__new__(mcls, name, bases, attrs)


class DynamicModel(metaclass=QueryBuilder):
    pass


def dynamic_class(extra: dict[str, Callable[..., Any]]):
    """type() builds classes at runtime with attacker-controlled methods."""
    return type("DynamicClass", (DynamicModel,), extra)


def add_method(instance: Any, name: str, fn: Callable[..., Any]) -> None:
    """Monkey-inject methods after instantiation."""
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
