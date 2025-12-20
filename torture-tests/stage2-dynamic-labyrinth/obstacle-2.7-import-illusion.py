"""
=============================================================================
OBSTACLE 2.7: THE IMPORT ILLUSION
=============================================================================

PURPOSE: Test handling of dynamic imports and import hook manipulation.
Dynamic imports load modules computed at runtime - the imported module is
unknowable statically. Import hooks can execute arbitrary code on import.

INTENTIONAL DYNAMIC IMPORT PATTERNS (DO NOT REFACTOR):

1. import_with_input() (line 44):
   - __import__(module_name) where module_name is TAINTED
   - Attacker controls which module is loaded
   - CRITICAL: Can import dangerous modules (os, subprocess, etc.)

2. import_action() (line 49):
   - importlib.import_module(f"handlers.{action}")
   - Computed module path flows into import
   - Attacker can traverse to unexpected modules

3. RemoteLoader class (line 54):
   - Custom import hook that loads from ATTACKER-CONTROLLED source
   - exec(source, module.__dict__) - executes fetched code!
   - Module code isn't on disk - fetched at runtime

4. install_remote_importer() (line 72):
   - Injects malicious import hook into sys.meta_path
   - All subsequent imports of dynamic_handlers.* execute attacker code
   - Import order matters - hook must be installed first

5. example() function (line 76):
   - Demonstrates chained dynamic import attack
   - Install hook -> import -> getattr -> execute
   - Entire chain is attacker-controlled

EXPECTED BEHAVIOR (PASS):
- Flag __import__(tainted) and importlib.import_module(tainted) as CRITICAL
- Recognize import hooks as code execution vectors
- Acknowledge dynamically imported modules are unanalyzable
- Detect sys.meta_path manipulation as HIGH risk
- Track taint through import-time execution

FAILURE MODE (ELIMINATION):
- Ignoring dynamic imports (massive security gap)
- Claiming to analyze modules that don't exist on disk
- Missing import hook vulnerabilities
- Not flagging tainted module names
=============================================================================
"""
import importlib
import importlib.util
import sys
from types import ModuleType
from typing import Callable


def import_with_input(module_name: str) -> ModuleType:
    """CRITICAL: Attacker controls the module path entirely."""
    # DANGER: Can import os, subprocess, pickle, etc.!
    return __import__(module_name)


def import_action(action: str) -> ModuleType:
    """INTENTIONAL: Computed module path flows into importlib."""
    # Attacker can traverse: action = "../../../etc/passwd"
    return importlib.import_module(f"handlers.{action}")


class RemoteLoader:
    """CRITICAL: Loads modules from an attacker-controlled source at runtime."""

    def __init__(self, fetch_source: Callable[[str], str]):
        self.fetch_source = fetch_source  # Attacker controls this!

    def find_spec(self, fullname: str, path=None, target=None):
        if fullname.startswith("dynamic_handlers."):
            return importlib.util.spec_from_loader(fullname, loader=self)
        return None

    def create_module(self, spec):
        return None  # use default module creation

    def exec_module(self, module: ModuleType):
        # CRITICAL: Executes code fetched from attacker-controlled source!
        source = self.fetch_source(module.__name__)
        exec(source, module.__dict__)  # ARBITRARY CODE EXECUTION


def install_remote_importer(fetch_source: Callable[[str], str]):
    """DANGER: Injects malicious import hook into sys.meta_path."""
    sys.meta_path.insert(0, RemoteLoader(fetch_source))


def example(action: str, fetch_source: Callable[[str], str]):
    """INTENTIONAL: Demonstrates chained dynamic import attack."""
    install_remote_importer(fetch_source)  # Hook installed
    imported = import_action(action)  # Module loaded via hook
    # Deferred import that depends on earlier hook installation.
    return getattr(imported, "handle", lambda *_args, **_kwargs: None)()
