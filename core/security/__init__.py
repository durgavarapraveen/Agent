"""
Core Security Subpackage
"""

import sys
import importlib

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.security.{name}")
    except ModuleNotFoundError:
        pass
    raise AttributeError(f"module 'core.security' has no attribute '{name}'")
