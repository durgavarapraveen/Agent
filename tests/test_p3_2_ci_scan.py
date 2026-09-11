"""Phase 3.2 — CI scan wrapper (severity gate + SARIF)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("ci_scan", ROOT / "scripts" / "ci_scan.py")
ci_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_scan)


def _findings():
    return [
        {"title": "XSS", "severity": "medium", "url": "https://a.test/x", "type": "xss"},
        {"title": "SQLi", "severity": "high", "url": "https://a.test/y", "type": "sqli"},
    ]


def test_severity_gate_fails_on_high():
    code, summary = ci_scan.severity_gate(_findings(), fail_on="high")
    assert code == 1
    assert summary["gate"] == "FAIL"
    assert summary["max_severity"] == "high"
    assert summary["over_threshold"] == 1


def test_severity_gate_passes_when_below_threshold():
    code, summary = ci_scan.severity_gate(_findings(), fail_on="critical")
    assert code == 0
    assert summary["gate"] == "PASS"      # high < critical
    assert summary["over_threshold"] == 0


def test_severity_gate_empty():
    code, summary = ci_scan.severity_gate([], fail_on="low")
    assert code == 0 and summary["max_severity"] == "none"


def test_build_sarif_shape():
    sarif = ci_scan.build_sarif(_findings(), target="https://a.test")
    assert sarif.get("version")
    assert "runs" in sarif and sarif["runs"]
    assert len(sarif["runs"][0]["results"]) == 2


def test_run_ci_scan_writes_outputs(tmp_path):
    sarif_out = tmp_path / "out.sarif"
    json_out = tmp_path / "out.json"
    code, summary = ci_scan.run_ci_scan(
        _findings(), target="https://a.test", fail_on="high",
        sarif_out=str(sarif_out), json_out=str(json_out))
    assert code == 1
    assert sarif_out.exists() and json_out.exists()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["summary"]["gate"] == "FAIL"
    assert len(data["findings"]) == 2


def test_load_findings_dict_and_list(tmp_path):
    p1 = tmp_path / "d.json"
    p1.write_text(json.dumps({"findings": _findings()}), encoding="utf-8")
    assert len(ci_scan.load_findings(str(p1))) == 2
    p2 = tmp_path / "l.json"
    p2.write_text(json.dumps(_findings()), encoding="utf-8")
    assert len(ci_scan.load_findings(str(p2))) == 2


def test_cli_main_gates_findings_file(tmp_path):
    f = tmp_path / "f.json"
    f.write_text(json.dumps(_findings()), encoding="utf-8")
    code = ci_scan.main([
        "--findings", str(f), "--fail-on", "high",
        "--sarif-out", str(tmp_path / "s.sarif"), "--json-out", str(tmp_path / "o.json"),
    ])
    assert code == 1
