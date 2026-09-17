"""Regression suite (P4 benchmarking) — asserts the benchmark corpora and the
eval-harness gate stay healthy. Pure/offline; live scans run separately in CI."""
from __future__ import annotations

from core.validation.benchmark_corpus import build_default_corpus
from core.validation.eval_harness import EvaluationHarness
from tests.benchmarks.juice_shop_benchmark import JUICE_SHOP_CHALLENGES, score_results
from tests.benchmarks.dvwa_benchmark import DVWA_CASES


def test_juice_shop_corpus_size():
    # Expanded corpus should keep growing toward the full 117.
    assert len(JUICE_SHOP_CHALLENGES) >= 40
    # every challenge maps to a non-empty vuln_class + executor
    for c in JUICE_SHOP_CHALLENGES:
        assert c.vuln_class and c.executor


def test_juice_shop_scoring_pure():
    catalog = JUICE_SHOP_CHALLENGES
    found = {c.id for c in catalog if c.category == "injection"}
    result = score_results(found, catalog)
    assert isinstance(result, dict) and result  # scorer returns a summary dict


def test_dvwa_corpus_present():
    assert len(DVWA_CASES) >= 5


def test_benchmark_corpus_coverage_gaps():
    corpus = build_default_corpus()
    # coverage_gaps must be callable (previously crashed export_report)
    gaps = corpus.coverage_gaps()
    assert isinstance(gaps, list)


def test_eval_harness_export_report_no_crash():
    corpus = build_default_corpus()
    harness = EvaluationHarness(corpus)
    harness.run_evaluation()
    report = harness.export_report()  # previously crashed on missing coverage_gaps()
    import json
    parsed = json.loads(report) if isinstance(report, str) else report
    assert isinstance(parsed, dict) and "metrics" in parsed
