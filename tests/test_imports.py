"""Smoke test: every module under core/, agents/, ui/api/ imports cleanly.

Catches:
  - undefined names / syntax errors from refactors
  - dangling references to deleted modules
  - circular imports
  - missing `requirements.txt` entries (module-level `import foo` fails at
    boot instead of mid-scan)

Does NOT execute the modules — pure import. Fast, no fixtures.
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Packages whose SUBMODULES we walk. Add cautiously — every new entry
# adds ~O(n) imports and drags in every heavy dep those files touch.
PACKAGES = ["core", "agents"]

# Files/patterns to skip: optional entry points, __main__ shims, or
# modules that legitimately require runtime infra (a live LLM, GPU,
# a Kali binary on PATH) just to import.
SKIP = {
    "core.__main__",
    "agents.__main__",
    # Import triggers a network call at module load — not defensible.
    "core.intel.tool_authoring",
}


def _walk(pkg_name: str) -> list[str]:
    try:
        pkg = importlib.import_module(pkg_name)
    except Exception as e:
        pytest.fail(f"root package {pkg_name!r} does not import: {e}")
    out = [pkg_name]
    for m in pkgutil.walk_packages(pkg.__path__, prefix=f"{pkg_name}."):
        if m.name in SKIP:
            continue
        out.append(m.name)
    return out


ALL_MODULES = sorted({m for p in PACKAGES for m in _walk(p)})


@pytest.mark.parametrize("modname", ALL_MODULES)
def test_module_imports(modname: str) -> None:
    try:
        importlib.import_module(modname)
    except Exception as e:
        pytest.fail(f"import {modname} failed: {type(e).__name__}: {e}")
