
import sys
import importlib

# Re-export primary module if present
try:
    from core.reporting.reporting import *  # noqa: F401,F403
except Exception:
    pass

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.reporting.{name}")
    except ModuleNotFoundError:
        pass
    try:
        main_m = importlib.import_module("core.reporting.reporting")
        if hasattr(main_m, name):
            return getattr(main_m, name)
    except Exception:
        pass
    raise AttributeError(f"module 'core.reporting' has no attribute '{name}'")
