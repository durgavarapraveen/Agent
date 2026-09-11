#!/usr/bin/env python3
"""Phase 10.1 / 10.3 — local (Ollama) model selection + performance tuning.

Detects available RAM/VRAM, recommends SMALL/LARGE models sized to the machine,
optionally pulls them via ``ollama pull``, and documents optimal Ollama runtime
settings. The recommendation logic is pure and testable; detection and pulling
are guarded so the script never crashes on a machine without psutil/Ollama.
"""
from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]

# Recommended Ollama runtime settings (Phase 10.3).
OLLAMA_TUNING = {
    "OLLAMA_NUM_PARALLEL": "4",        # parallel request handling
    "OLLAMA_MAX_LOADED_MODELS": "2",   # keep SMALL + LARGE resident
    "OLLAMA_KEEP_ALIVE": "30m",        # don't unload between calls
}


def detect_ram_gb() -> float:
    try:
        import psutil
        return round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:
        return 0.0


def detect_vram_gb() -> float:
    """Best-effort NVIDIA VRAM detection via nvidia-smi; 0 if unavailable."""
    smi = shutil.which("nvidia-smi")
    if not smi:
        return 0.0
    try:
        out = subprocess.run(
            [smi, "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10)
        mbs = [int(x) for x in out.stdout.split() if x.strip().isdigit()]
        return round(max(mbs) / 1024, 1) if mbs else 0.0
    except Exception:
        return 0.0


def recommend_models(ram_gb: float, vram_gb: float = 0.0) -> Dict[str, str]:
    """Recommend SMALL/LARGE models for the available memory (plan 10.1 tiers)."""
    if ram_gb < 16:
        return {"small": "qwen3:8b", "large": "api",
                "note": "<16GB RAM — run SMALL locally, use a cloud API for LARGE",
                "quality": "basic"}
    if ram_gb < 32:
        return {"small": "qwen3:14b", "large": "api",
                "note": "16-32GB RAM — SMALL local, cloud API for LARGE",
                "quality": "good"}
    if ram_gb < 64:
        return {"small": "qwen3:14b", "large": "qwen3:32b",
                "note": "32-64GB RAM — both tiers local", "quality": "very good"}
    return {"small": "qwen3:14b", "large": "qwen3:72b",
            "note": "64GB+ RAM — large local models", "quality": "excellent"}


def ollama_available() -> bool:
    return shutil.which("ollama") is not None


def pull_model(model: str) -> bool:
    if model in ("api", "") or not ollama_available():
        return False
    try:
        subprocess.run(["ollama", "pull", model], check=True, timeout=3600)
        return True
    except Exception as e:
        logger.warning("ollama pull %s failed: %s", model, e)
        return False


def tuning_report() -> str:
    lines = ["Recommended Ollama runtime settings (Phase 10.3):"]
    for k, v in OLLAMA_TUNING.items():
        lines.append(f"  export {k}={v}")
    lines.append("  # GPU: run `ollama serve` with full offload (--num-gpu 999) when a GPU is present")
    return "\n".join(lines)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description="Recommend/pull local Ollama models")
    parser.add_argument("--pull", action="store_true", help="Pull the recommended models")
    args = parser.parse_args(argv)

    ram, vram = detect_ram_gb(), detect_vram_gb()
    rec = recommend_models(ram, vram)
    print(f"Detected: RAM={ram}GB VRAM={vram}GB")
    print(f"Recommended: SMALL={rec['small']} LARGE={rec['large']} ({rec['quality']})")
    print(f"  {rec['note']}")
    print(tuning_report())

    if args.pull:
        if not ollama_available():
            print("Ollama is not installed — skipping pull. See https://ollama.com")
            return 1
        for m in (rec["small"], rec["large"]):
            if m != "api":
                print(f"Pulling {m} ...")
                pull_model(m)
    return 0


if __name__ == "__main__":
    sys.exit(main())
