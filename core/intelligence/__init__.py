
import sys
import importlib

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.intelligence.{name}")
    except ModuleNotFoundError:
        pass
    raise AttributeError(f"module 'core.intelligence' has no attribute '{name}'")
