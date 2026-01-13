"""
=============================================================================
OBSTACLE 2.5: MONKEY PATCH MAYHEM
=============================================================================

PURPOSE: Test detection of runtime monkey patches that invalidate static analysis.
Monkey patching replaces functions/methods at runtime - the source code you see
is NOT the code that executes. Static analysis of the original is INVALID.

INTENTIONAL MONKEY PATCHES (DO NOT REMOVE):

1. patch_builtins() (line 46):
   - Replaces built-in open() with malicious version
   - WRITES TO /etc/passwd regardless of argument!
   - Any code calling open() after this is compromised

2. patch_auth_module() (line 51):
   - Disables authentication by overwriting check()
   - Returns True for ALL tokens - auth bypass!
   - Static analysis of original check() is meaningless

3. patch_logger() (line 57):
   - Silences security error logs at runtime
   - Errors occur but go unreported
   - Security monitoring is blinded

4. apply_patches() (line 61):
   - Applies all patches then uses patched code
   - auth.check("any-token") returns True (should be False!)
   - Downstream calls execute patched behavior

EXPECTED BEHAVIOR (PASS):
- Detect setattr/assignment to existing functions
- Recognize builtins modification as CRITICAL
- Mark patched code paths with reduced confidence
- Acknowledge static analysis is invalidated
- Track which functions were replaced

FAILURE MODE (ELIMINATION):
- Analyzing original function when patched version executes
- Missing auth bypass vulnerability
- Claiming security based on original source
- Not flagging builtins modification
=============================================================================
"""
import builtins
import logging
from types import ModuleType

original_open = open


class Authenticator:
    def check(self, token: str) -> bool:
        return token == "expected-token"


auth = Authenticator()


def patch_builtins():
    """CRITICAL: Replace built-in open() with malicious version."""
    # INTENTIONAL: Writes to /etc/passwd regardless of arguments!
    builtins.open = lambda *_args, **_kwargs: original_open("/etc/passwd", "w")


def patch_auth_module(module: ModuleType):
    """CRITICAL: Disable authentication by overwriting implementation."""
    # INTENTIONAL: Always returns True - complete auth bypass!
    module.check = lambda *_args, **_kwargs: True
    auth.check = module.check


def patch_logger():
    """INTENTIONAL: Silence security logs at runtime."""
    # Security errors occur but are silently swallowed
    logging.Logger.error = lambda self, msg, *args, **kwargs: None


def apply_patches(module: ModuleType):
    """INTENTIONAL: Applies all patches, then uses patched code."""
    patch_builtins()
    patch_auth_module(module)
    patch_logger()
    # DANGER: auth.check now always returns True!
    # Downstream calls now execute patched behavior rather than static source.
    return auth.check("any-token")
