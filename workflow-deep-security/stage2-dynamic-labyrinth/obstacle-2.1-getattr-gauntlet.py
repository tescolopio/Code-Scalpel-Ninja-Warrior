"""
=============================================================================
OBSTACLE 2.1: THE GETATTR GAUNTLET
=============================================================================

PURPOSE: Test taint tracking through Python's dynamic attribute access.
getattr/setattr/__getattr__ allow attribute names to be computed at runtime,
making static analysis fundamentally impossible in the general case.

INTENTIONAL DYNAMIC PATTERNS (DO NOT REFACTOR TO STATIC):

1. RedisProxy.__getattr__ (line 22):
   - Proxies attribute access to external backing dict
   - Attribute values come from dynamic source (Redis, dict, etc.)
   - Static analysis CANNOT know what attributes exist

2. dynamic_fetch() (line 28):
   - getattr(config, user_input) where user_input is TAINTED
   - Attacker controls the attribute name entirely
   - MUST treat result as tainted with reduced confidence

3. chained_lookup() (line 33):
   - getattr(getattr(obj, first), second) - double indirection
   - Makes target resolution even more opaque
   - Each hop adds uncertainty

4. install_dynamic() (line 38):
   - setattr injects tainted callable at runtime
   - Analysis cannot predict what methods exist after setattr

EXPECTED BEHAVIOR (PASS):
- Recognize dynamic attribute targets cannot be statically resolved
- Mark results of getattr(obj, user_input) as tainted
- Reduce confidence due to dynamic nature
- NOT claim to know which attribute is accessed
- Track taint through setattr modifications

FAILURE MODE (ELIMINATION):
- Ignoring getattr entirely (false negatives)
- Incorrectly resolving the attribute name (false positives)
- Claiming high confidence about unknowable access
=============================================================================
"""
from typing import Any, Callable


class RedisProxy:
    """INTENTIONAL: Proxies attribute access to external system."""

    def __init__(self, backing: dict[str, Any]):
        self.backing = backing

    def __getattr__(self, name: str) -> Any:
        # INTENTIONAL: Attribute values pulled from dynamic source
        # Static analysis CANNOT know what attributes exist
        return self.backing.get(name, f"missing:{name}")


def dynamic_fetch(config: Any, user_input: str) -> Any:
    """INTENTIONAL: Attacker controls the attribute name."""
    # DANGER: user_input is tainted - we can't know which attribute is accessed!
    return getattr(config, user_input)


def chained_lookup(obj: Any, first: str, second: str) -> Any:
    """INTENTIONAL: Chained getattr makes target resolution opaque."""
    # Double indirection - each hop adds uncertainty
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
