"""
Factory/closure patterns that generate new callables capturing tainted values.
Expected: Taint should propagate through closures and decorator transformations.
"""
from functools import wraps
from typing import Callable


def handler_factory(table_name: str) -> Callable[[str], str]:
    captured_table = table_name  # attacker can choose table at runtime

    def handler(user_input: str) -> str:
        return f"SELECT * FROM {captured_table} WHERE id = {user_input}"

    return handler


def decorator_injector(transform: Callable[[str], str]):
    def decorate(fn: Callable[[str], str]):
        @wraps(fn)
        def wrapper(user_value: str) -> str:
            # Captured transform modifies the tainted value.
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
