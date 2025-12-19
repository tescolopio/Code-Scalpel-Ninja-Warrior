"""
Dynamic attribute access driven by tainted input.
Expected: Code Scalpel should treat results as tainted and avoid
claiming which attribute is resolved.
"""
from typing import Any, Callable


class RedisProxy:
    """Pretends to fetch attributes from an external system."""

    def __init__(self, backing: dict[str, Any]):
        self.backing = backing

    def __getattr__(self, name: str) -> Any:
        # Attribute values are pulled from a dynamic source.
        return self.backing.get(name, f"missing:{name}")


def dynamic_fetch(config: Any, user_input: str) -> Any:
    """Attacker controls the attribute name."""
    return getattr(config, user_input)


def chained_lookup(obj: Any, first: str, second: str) -> Any:
    """Chained getattr makes target resolution even more opaque."""
    return getattr(getattr(obj, first), second)


def install_dynamic(target: Any, key: str, value: Callable[..., Any]) -> Callable[..., Any]:
    """setattr uses tainted input to modify behavior at runtime."""
    setattr(target, key, value)
    return getattr(target, key)


def example(config: Any, external_state: dict[str, Any], user_supplied_key: str) -> Any:
    proxy = RedisProxy(external_state)
    # Access flows through __getattr__, then uses the tainted key again.
    setattr(config, "live_proxy", proxy)
    return chained_lookup(config, "live_proxy", user_supplied_key)
