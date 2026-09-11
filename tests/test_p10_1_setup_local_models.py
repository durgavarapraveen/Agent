"""Phase 10.1 / 10.3 — local model selection & Ollama tuning."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("setup_local_models",
                                               ROOT / "scripts" / "setup_local_models.py")
slm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(slm)


def test_recommend_low_ram():
    rec = slm.recommend_models(8)
    assert rec["small"] == "qwen3:8b"
    assert rec["large"] == "api"


def test_recommend_mid_ram():
    assert slm.recommend_models(24)["small"] == "qwen3:14b"
    assert slm.recommend_models(24)["large"] == "api"


def test_recommend_high_ram():
    rec = slm.recommend_models(48)
    assert rec["small"] == "qwen3:14b"
    assert rec["large"] == "qwen3:32b"


def test_recommend_very_high_ram():
    assert slm.recommend_models(128)["large"] == "qwen3:72b"


def test_tuning_report_has_settings():
    report = slm.tuning_report()
    assert "OLLAMA_NUM_PARALLEL=4" in report
    assert "OLLAMA_KEEP_ALIVE=30m" in report
    assert "OLLAMA_MAX_LOADED_MODELS=2" in report


def test_tuning_constants():
    assert slm.OLLAMA_TUNING["OLLAMA_NUM_PARALLEL"] == "4"


def test_detect_ram_returns_float():
    # psutil is installed in this env; RAM should be > 0.
    assert isinstance(slm.detect_ram_gb(), float)


def test_main_runs_without_pull(capsys):
    rc = slm.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Recommended:" in out and "Ollama" in out
