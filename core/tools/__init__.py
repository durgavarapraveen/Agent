"""
Core Tools Subpackage
"""

import sys
import importlib

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.tools.{name}")
    except ModuleNotFoundError:
        pass
    raise AttributeError(f"module 'core.tools' has no attribute '{name}'")
