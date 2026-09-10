from __future__ import annotations

import functools
import sys


def _has(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:
        return False


@functools.lru_cache(maxsize=1)
def get_profile() -> dict:
    return {
        "python_version": sys.version.split()[0],
        "custom_python_sandbox": {
            "preloaded_modules": ["httpx (async, scope-limited)", "asyncio",
                                  "json", "re", "time"],
            "helpers": ["target_base"],
            "top_level_await": True,
            "result_contract": "assign the final value to RESULT",
            "timeout_seconds": 30,
            "max_code_bytes": 8192,
            "unavailable": ["os", "subprocess", "socket", "pathlib", "open()",
                            "__import__", "eval/exec", "importlib", "playwright",
                            "filesystem", "arbitrary network"],
            "network": "only authorised target hosts (httpx is scope-wrapped)",
        },
        "host_modules": {"httpx": _has("httpx"), "playwright": _has("playwright")},
    }


def describe_for_llm() -> str:
    p = get_profile()
    sb = p["custom_python_sandbox"]
    return (
        "## Execution Environment (fixed — do NOT probe it)\n"
        f"Python {p['python_version']}. The `run_custom_python` sandbox preloads: "
        f"{', '.join(sb['preloaded_modules'])} plus `target_base`. "
        "Top-level `await` works. Assign your result to `RESULT`. "
        f"Timeout {sb['timeout_seconds']}s; code must be <= {sb['max_code_bytes'] // 1024}KB. "
        f"NOT available inside the sandbox: {', '.join(sb['unavailable'])}. "
        f"Network: {sb['network']}. "
        "Do not write snippets to test module availability, async support, or the "
        "sandbox API — the above is authoritative and will not change during the scan.\n\n"
    )
