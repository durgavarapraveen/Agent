"""
Core Memory Subpackage
"""

import sys
import importlib

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.memory.{name}")
    except ModuleNotFoundError:
        pass
    raise AttributeError(f"module 'core.memory' has no attribute '{name}'")
