
import os
import sys
import importlib

# Define subpackages
SUBPACKAGES = [
    "orchestration",
    "tools",
    "intelligence",
    "exploitation",
    "memory",
    "reporting",
    "security",
    "common"
]

# Add all subpackage directories to core's __path__ so Python's native import machinery
# resolves both `core.orchestration.central_brain` and `core.central_brain` automatically.
_current_dir = os.path.dirname(__file__)
for _subpkg in SUBPACKAGES:
    _subpkg_dir = os.path.join(_current_dir, _subpkg)
    if os.path.isdir(_subpkg_dir) and _subpkg_dir not in __path__:
        __path__.append(_subpkg_dir)

# Map legacy module names for explicit __getattr__ access
_MODULE_MAP = {}
for _subpkg in SUBPACKAGES:
    _subpkg_dir = os.path.join(_current_dir, _subpkg)
    if os.path.isdir(_subpkg_dir):
        for _fname in os.listdir(_subpkg_dir):
            if _fname.endswith(".py") and not _fname.startswith("__"):
                _mod_name = _fname[:-3]
                _MODULE_MAP[_mod_name] = f"core.{_subpkg}.{_mod_name}"

def __getattr__(name: str):
    if name in _MODULE_MAP:
        mod = importlib.import_module(_MODULE_MAP[name])
        return mod
    elif name in SUBPACKAGES:
        return importlib.import_module(f"core.{name}")
    raise AttributeError(f"module 'core' has no attribute '{name}'")
