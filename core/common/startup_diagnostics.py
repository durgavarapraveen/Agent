"""
Startup diagnostics — logs runtime identity so stale-image / wrong-module
bugs are caught immediately.
"""

import inspect
import logging
import os
import platform
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

BUILD_ID = os.environ.get("BUILD_ID", "dev")
CONTAINER_ID = os.environ.get("HOSTNAME", "bare-metal")


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode().strip()
    except Exception:
        return "unknown"


def _module_source(cls) -> str:
    try:
        return inspect.getfile(cls)
    except (TypeError, OSError):
        return "built-in/unknown"


def log_startup_diagnostics() -> None:
    git_commit = _git_commit()
    project_root = str(Path(__file__).resolve().parent.parent.parent)

    header = [
        "=" * 60,
        "STARTUP DIAGNOSTICS",
        f"  BUILD_ID       : {BUILD_ID}",
        f"  GIT_COMMIT     : {git_commit}",
        f"  PYTHON_VERSION : {platform.python_version()}",
        f"  PYTHON_EXEC    : {sys.executable}",
        f"  PROJECT_ROOT   : {project_root}",
        f"  CONTAINER_ID   : {CONTAINER_ID}",
        f"  PLATFORM       : {platform.platform()}",
        f"  CWD            : {os.getcwd()}",
    ]

    critical_classes = {
        "SharedContextV2": "core.memory.shared_context",
        "CentralBrain": "core.orchestration.central_brain",
        "TaskManager": "core.orchestration.task_manager",
        "TaskStateMachine": "core.domain.task_state_machine",
        "CapabilityRegistry": "core.tools.tool_definitions",
        "ToolRegistry": "core.tools.tool_registry",
        "FindingStateMachine": "core.findings.finding_state_machine",
    }

    header.append("  MODULE SOURCE PATHS:")
    for class_name, module_path in critical_classes.items():
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name, None)
            if cls:
                header.append(f"    {class_name:30s} -> {_module_source(cls)}")
            else:
                header.append(f"    {class_name:30s} -> CLASS NOT FOUND in {module_path}")
        except ImportError as e:
            header.append(f"    {class_name:30s} -> IMPORT ERROR: {e}")

    header.append("=" * 60)

    for line in header:
        logger.info(line)
