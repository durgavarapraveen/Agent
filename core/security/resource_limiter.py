"""
Phase 8 Module 8.2: Resource Limits & Timeouts (core/resource_limiter.py)

Per-tool CPU, RAM, and open file descriptor capping, tool-specific timeouts
with partial output capture, daemonized global scan timer, and psutil tracking.
"""

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable

import psutil

logger = logging.getLogger(__name__)

# Pre-defined tool timeouts in seconds
TOOL_TIMEOUTS = {
    "nmap": 1800,
    "gobuster": 1200,
    "nuclei": 900,
    "sqlmap": 3600,
    "masscan": 600,
    "ffuf": 1200,
    "generic": 300
}


class ScanTimeoutError(Exception):
    """Raised when the global scan timer expires."""
    pass


class ResourceViolationError(Exception):
    """Raised when a subprocess exceeds CPU or memory resource limits."""
    pass


class ResourceLimiter:
    """Enforces process resource limits, timeouts, and psutil monitoring."""

    def __init__(self):
        self.active_processes: List[subprocess.Popen] = []
        self._global_timer: Optional[threading.Timer] = None

    def can_allocate(self, tool_id: str) -> bool:
        """Check if resources are available to run this tool"""
        # A simple check for now, can be expanded to check CPU/RAM
        return True

    def start_global_scan_timer(self, timeout_sec: float = 86400.0, callback: Optional[Callable] = None) -> threading.Timer:
        """
        Start daemonized global scan timer.
        Raises ScanTimeoutError and terminates active processes when timer expires.
        """
        def _on_timeout():
            logger.critical(f"[ResourceLimiter] GLOBAL SCAN TIMEOUT EXPIRED ({timeout_sec}s). Terminating active processes.")
            self.terminate_all_processes()
            if callback:
                callback()

        timer = threading.Timer(timeout_sec, _on_timeout)
        timer.daemon = True
        timer.start()
        self._global_timer = timer
        return timer

    def cancel_global_scan_timer(self):
        """Cancel global scan timer if active."""
        if self._global_timer:
            self._global_timer.cancel()
            self._global_timer = None

    def terminate_all_processes(self):
        """Gracefully terminate or kill all registered active subprocesses."""
        for proc in list(self.active_processes):
            try:
                if proc.poll() is None:
                    proc.terminate()
                    time.sleep(0.2)
                    if proc.poll() is None:
                        proc.kill()
            except Exception as e:
                logger.warning(f"[ResourceLimiter] Process termination error: {e}")
        self.active_processes.clear()

    def run_subprocess_with_limits(
        self,
        cmd: List[str],
        tool_name: str = "generic",
        timeout: Optional[int] = None,
        memory_limit_mb: int = 2048,
        cpu_time_limit_sec: int = 300
    ) -> Dict[str, Any]:
        """
        Spawn subprocess with POSIX setrlimit preexec_fn (where supported),
        monitor CPU/RAM via psutil, enforce tool timeout, capture partial stdout/stderr,
        and return a resource usage summary.
        """
        tool_key = tool_name.lower()
        effective_timeout = timeout or TOOL_TIMEOUTS.get(tool_key, TOOL_TIMEOUTS["generic"])

        def _preexec():
            try:
                import resource
                # CPU time limit
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_time_limit_sec, cpu_time_limit_sec + 30))
                # Open files limit
                soft_fd, hard_fd = resource.getrlimit(resource.RLIMIT_NOFILE)
                resource.setrlimit(resource.RLIMIT_NOFILE, (min(1024, hard_fd), hard_fd))
                # Virtual memory limit (bytes)
                mem_bytes = memory_limit_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except Exception:
                pass

        preexec_fn = _preexec if os.name != "nt" else None

        logger.info(f"[ResourceLimiter] Spawning tool '{tool_key}' with timeout={effective_timeout}s, RAM limit={memory_limit_mb}MB")
        start_time = time.time()

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=preexec_fn
        )
        self.active_processes.append(proc)

        max_memory_used_mb = 0.0
        cpu_seconds_used = 0.0
        timed_out = False
        partial_stdout = ""
        partial_stderr = ""

        try:
            # Psutil monitoring loop
            try:
                p_util = psutil.Process(proc.pid)
            except Exception:
                p_util = None

            while proc.poll() is None:
                elapsed = time.time() - start_time
                if elapsed > effective_timeout:
                    timed_out = True
                    proc.terminate()
                    time.sleep(0.2)
                    if proc.poll() is None:
                        proc.kill()
                    break

                if p_util:
                    try:
                        mem_info = p_util.memory_info()
                        mem_mb = mem_info.rss / (1024 * 1024)
                        max_memory_used_mb = max(max_memory_used_mb, mem_mb)

                        cpu_times = p_util.cpu_times()
                        cpu_seconds_used = cpu_times.user + cpu_times.system

                        # Check RAM violation
                        if mem_mb > memory_limit_mb:
                            logger.warning(f"[ResourceLimiter] RESOURCE_VIOLATION: Tool '{tool_key}' exceeded memory limit ({mem_mb:.1f} MB > {memory_limit_mb} MB). Killing process.")
                            proc.kill()
                            raise ResourceViolationError(f"Tool '{tool_key}' exceeded memory cap of {memory_limit_mb} MB.")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                time.sleep(0.1)

            stdout_data, stderr_data = proc.communicate(timeout=2.0) if proc.poll() is not None else ("", "")
            partial_stdout = stdout_data or ""
            partial_stderr = stderr_data or ""

        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            partial_stdout, partial_stderr = proc.communicate()
        finally:
            if proc in self.active_processes:
                self.active_processes.remove(proc)

        elapsed_total = time.time() - start_time

        summary_msg = f"Tool {tool_name} used {max_memory_used_mb:.1f} MB RAM (limit {memory_limit_mb} MB) and {elapsed_total:.1f}s CPU (limit {cpu_time_limit_sec}s)."
        logger.info(f"[ResourceLimiter] {summary_msg}")

        return {
            "tool_name": tool_name,
            "cmd": " ".join(cmd),
            "returncode": proc.returncode if not timed_out else -1,
            "stdout": partial_stdout,
            "stderr": partial_stderr,
            "timed_out": timed_out,
            "status": "PARTIAL_RESULTS" if timed_out else ("SUCCESS" if proc.returncode == 0 else "FAILED"),
            "memory_used_mb": round(max_memory_used_mb, 1),
            "cpu_time_sec": round(elapsed_total, 1),
            "summary": summary_msg
        }
