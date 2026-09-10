
import sys
import importlib

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.common.{name}")
    except ModuleNotFoundError:
        pass
    raise AttributeError(f"module 'core.common' has no attribute '{name}'")
