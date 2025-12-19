"""
Dynamic imports and import hook manipulation.
Expected: Tainted module names must be treated as critical; unknown modules
should be acknowledged as unanalyzable.
"""
import importlib
import importlib.util
import sys
from types import ModuleType
from typing import Callable


def import_with_input(module_name: str) -> ModuleType:
    # Attacker controls the module path entirely.
    return __import__(module_name)


def import_action(action: str) -> ModuleType:
    # Computed module path flows into importlib.
    return importlib.import_module(f"handlers.{action}")


class RemoteLoader:
    """Loads modules from an attacker-controlled source at runtime."""

    def __init__(self, fetch_source: Callable[[str], str]):
        self.fetch_source = fetch_source

    def find_spec(self, fullname: str, path=None, target=None):
        if fullname.startswith("dynamic_handlers."):
            return importlib.util.spec_from_loader(fullname, loader=self)
        return None

    def create_module(self, spec):
        return None  # use default module creation

    def exec_module(self, module: ModuleType):
        source = self.fetch_source(module.__name__)
        exec(source, module.__dict__)


def install_remote_importer(fetch_source: Callable[[str], str]):
    sys.meta_path.insert(0, RemoteLoader(fetch_source))


def example(action: str, fetch_source: Callable[[str], str]):
    install_remote_importer(fetch_source)
    imported = import_action(action)
    # Deferred import that depends on earlier hook installation.
    return getattr(imported, "handle", lambda *_args, **_kwargs: None)()
