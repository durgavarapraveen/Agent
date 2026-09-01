"""
Core Orchestration Subpackage
"""

import sys
import importlib

def __getattr__(name: str):
    try:
        return importlib.import_module(f"core.orchestration.{name}")
    except ModuleNotFoundError:
        pass
    raise AttributeError(f"module 'core.orchestration' has no attribute '{name}'")
