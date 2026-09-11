"""Phase 6.1 — persistent LLM cost tracking."""
from __future__ import annotations

from types import SimpleNamespace

from core.economics.cost_log import CostLogEntry, LLMCostLog


def test_record_and_totals():
    log = LLMCostLog()
    log.record("scan1", "deepseek", "deepseek-chat", input_tokens=1000,
               output_tokens=500, cost_usd=0.01)
    log.record("scan1", "deepseek", "deepseek-chat", input_tokens=2000,
               output_tokens=800, cost_usd=0.02)
    log.record("scan2", "ollama", "qwen", cost_usd=0.0)
    assert log.get_total_cost("scan1") == 0.03
    assert log.get_total_cost("scan2") == 0.0


def test_breakdown_by_model_and_provider():
    log = LLMCostLog()
    log.record("s", "deepseek", "deepseek-chat", input_tokens=100, cost_usd=0.01)
    log.record("s", "bedrock", "claude", input_tokens=200, cost_usd=0.05)
    bd = log.get_cost_breakdown("s")
    assert bd["requests"] == 2
    assert bd["total_cost_usd"] == 0.06
    assert bd["by_model"]["deepseek/deepseek-chat"]["cost_usd"] == 0.01
    assert bd["by_provider"]["bedrock"] == 0.05
    assert bd["total_input_tokens"] == 300


def test_from_budget_ingestion():
    budget = SimpleNamespace(requests=[
        SimpleNamespace(provider="deepseek", model="deepseek-chat",
                        input_tokens=10, output_tokens=5, cost_usd=0.001, timestamp="t1"),
        SimpleNamespace(provider="deepseek", model="deepseek-chat",
                        input_tokens=20, output_tokens=8, cost_usd=0.002, timestamp="t2"),
    ])
    log = LLMCostLog()
    n = log.from_budget(budget, "scanX")
    assert n == 2
    assert log.get_total_cost("scanX") == 0.003


def test_persist_callback_invoked():
    persisted = []
    log = LLMCostLog(persist=lambda e: persisted.append(e))
    log.record("s", "p", "m", cost_usd=0.5)
    assert len(persisted) == 1 and isinstance(persisted[0], CostLogEntry)


def test_persist_failure_does_not_raise():
    def boom(entry):
        raise RuntimeError("db down")
    log = LLMCostLog(persist=boom)
    # Must not raise — cost logging can't break a scan.
    log.record("s", "p", "m", cost_usd=0.1)
    assert log.get_total_cost("s") == 0.1


def test_scan_isolation():
    log = LLMCostLog()
    log.record("a", "p", "m", cost_usd=1.0)
    log.record("b", "p", "m", cost_usd=2.0)
    assert log.get_total_cost("a") == 1.0
    assert len(log.entries_for("b")) == 1
