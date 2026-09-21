"""Recall harness tests.

Offline tests always run (validate the scorer + catalogs). The LIVE recall run
is gated on RECALL_TARGET so unit CI stays hermetic; the scheduled recall CI job
sets RECALL_TARGET against a Juice Shop container.
"""
from __future__ import annotations

import os
import pytest

from core.validation.recall_harness import (
    score, KnownVuln, juice_shop_catalog, _norm_class,
)


def test_class_normalization():
    assert _norm_class("sql-injection") == "SQLI"
    assert _norm_class("Reflected XSS") == "XSS"
    assert _norm_class("os_command_injection") == "RCE"


def test_scorer_recall_and_miss_list():
    catalog = [
        KnownVuln("c1", "SQLI"), KnownVuln("c2", "XSS"), KnownVuln("c3", "IDOR"),
    ]
    findings = [
        {"type": "sql_injection", "confirmed": True},
        {"type": "XSS", "confirmed": True},
    ]
    r = score(findings, catalog)
    assert r.total_known == 3
    assert r.detected == 2
    assert 0.66 <= r.recall <= 0.67
    assert [m["id"] for m in r.miss_list] == ["c3"]
    assert r.precision == 1.0


def test_scorer_precision_penalizes_unmapped_confirmed():
    catalog = [KnownVuln("c1", "SQLI")]
    findings = [
        {"type": "sqli", "confirmed": True},
        {"type": "SOME_NOISE_CLASS", "confirmed": True},  # not in catalog
    ]
    r = score(findings, catalog)
    assert r.recall == 1.0
    assert r.precision == 0.5


def test_juice_shop_catalog_loads():
    cat = juice_shop_catalog()
    assert len(cat) >= 40
    assert all(k.nclass for k in cat)


@pytest.mark.skipif(not os.getenv("RECALL_TARGET"),
                    reason="live recall run requires RECALL_TARGET (a running lab)")
def test_live_recall_meets_threshold():
    import asyncio
    from scripts.run_recall import _scan
    findings = asyncio.run(_scan(os.environ["RECALL_TARGET"]))
    catalog = juice_shop_catalog()
    r = score(findings, catalog)
    threshold = float(os.getenv("RECALL_MIN", "0"))
    assert r.recall >= threshold, f"recall {r.recall:.2%} < {threshold:.2%}; misses={len(r.miss_list)}"
