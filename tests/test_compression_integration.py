"""
Integration tests for Capability Worker Token Compression Pipeline.
Tests Layer 1 (Dedup), Layer 2 (Significance Filter & Compression & Error Translation), and Layer 3 (Shared Context).
"""

import time
import pytest
from typing import Dict, Any

from core.capability_worker import CapabilityWorker
from core.config import get_config
from core.schemas import CapabilityType, ToolExecutionStatus
from core.tool_registry import ToolRegistry


class DummySharedContext(list):
    """Mock shared context implementing append and tool_results tracking."""
    def __init__(self):
        super().__init__()
        self.tool_results = {}

    def add_tool_result(self, tool: str, summary: str):
        self.tool_results[tool] = summary
        self.append(summary)


@pytest.fixture
def worker():
    registry = ToolRegistry()
    context = DummySharedContext()
    return CapabilityWorker(agent_id="AGENT-INTEGRATION-TEST", tool_registry=registry, shared_context=context)


def test_full_recon_workflow_compression(worker):
    """
    Run full recon workflow with compression enabled:
    subfinder -> nmap -> sslscan -> paramspider
    Measures total tokens before and after compression, verifying >80% token savings and zero insight loss.
    """
    config = get_config()
    config.token_compression = True
    config.compression_threshold = 50
    config.dedup_enabled = True
    config.significance_filter_enabled = True
    config.error_translation_enabled = True

    ts = int(time.time() * 1000)
    target = f"target-{ts}.com"
    raw_outputs = [
        ("subfinder", "subdomain_enumeration", {
            "success": True,
            "returncode": 0,
            "output": "\n".join([f"subdomain-{i:04d}-{ts}.{target}" for i in range(1, 400)]),
            "data": {}
        }),
        ("nmap", "port_scanning", {
            "success": True,
            "returncode": 0,
            "output": "\n".join([f"{p}/tcp open http_service_endpoint_{p}" for p in range(1000, 4000)]),
            "data": {}
        }),
        ("sslscan", "ssl_tls_analysis", {
            "success": True,
            "returncode": 0,
            "output": "TLSv1.0 enabled\nTLSv1.1 enabled\nSSLv3 enabled\n" + ("Verbose cipher breakdown details line\n" * 800),
            "data": {
                "protocols": ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
                "weak_ciphers": ["RC4-SHA", "DES-CBC3-SHA"],
                "vulnerabilities": ["POODLE", "BEAST"]
            }
        }),
        ("paramspider", "endpoint_discovery", {
            "success": True,
            "returncode": 0,
            "output": "\n".join([
                f"https://{target}/static/style.css",
                f"https://{target}/api/v1/users?id=123",
                f"https://{target}/admin/login",
                f"https://{target}/upload?file=test"
            ] + [f"https://{target}/assets/static_image_asset_{i}.png" for i in range(300)]),
            "data": {}
        })
    ]

    total_raw_tokens = 0
    total_compressed_tokens = 0

    for tool_name, cap, raw_res in raw_outputs:
        raw_payload = str(raw_res.get("output", "")) + str(raw_res.get("data", {}))
        raw_tokens = max(1, len(raw_payload) // 4)
        total_raw_tokens += raw_tokens

        result = worker._process_raw_tool_result(tool_name, cap, target, raw_res)

        comp_payload = str(result.stdout) + str(result.data)
        comp_tokens = max(1, len(comp_payload) // 4)
        total_compressed_tokens += comp_tokens

        assert result.status in (ToolExecutionStatus.SUCCESS, ToolExecutionStatus.PARTIAL_SUCCESS)
        assert len(result.stdout) > 0

    # 1. Token reduction verification (> 80% saved overall)
    pct_saved = (1.0 - (total_compressed_tokens / total_raw_tokens)) * 100
    assert pct_saved > 80.0, f"Expected > 80% token savings, got {pct_saved:.1f}%"

    # 2. Verify no loss of critical findings
    subfinder_res = worker.ctx.tool_results.get("subfinder") or str(worker.ctx)
    assert "subfinder" in subfinder_res.lower() or "status: success" in subfinder_res.lower()

    paramspider_res = worker._process_raw_tool_result("paramspider", "endpoint_discovery", target, raw_outputs[3][2])
    endpoints = paramspider_res.data.get("endpoints", [])
    urls = [ep if isinstance(ep, str) else ep.get("url", "") for ep in endpoints]
    assert any("/api/" in u or "/admin" in u or "/upload" in u for u in urls), "Critical endpoints were lost during filtering!"
    assert not any(u.endswith(".png") for u in urls), "Static noise (.png) was not filtered out!"


def test_dedup_layer_toggle(worker):
    """Verify deduplication layer can be toggled via config."""
    config = get_config()
    ts = int(time.time() * 1000)
    target = f"dedup-test-{ts}.com"
    raw_res = {
        "success": True,
        "returncode": 0,
        "output": f"sub1-{ts}.{target}\nsub2-{ts}.{target}",
        "data": {}
    }

    # Run 1: Register brand new findings
    config.dedup_enabled = True
    res1 = worker._process_raw_tool_result("subfinder", "subdomain_enumeration", target, raw_res)
    assert "DEDUPLICATED" not in res1.stdout

    # Run 2: Exact duplicate run with dedup enabled
    res2 = worker._process_raw_tool_result("subfinder", "subdomain_enumeration", target, raw_res)
    assert "DEDUPLICATED" in res2.stdout

    # Run 3: Exact duplicate run with dedup disabled
    config.dedup_enabled = False
    res3 = worker._process_raw_tool_result("subfinder", "subdomain_enumeration", target, raw_res)
    assert "DEDUPLICATED" not in res3.stdout


def test_error_translation_layer(worker):
    """Verify ErrorTranslator layer produces human-readable diagnostics for failed tools."""
    config = get_config()
    config.error_translation_enabled = True

    raw_res = {
        "success": False,
        "returncode": 1,
        "output": "",
        "error": "Connection refused on port 443 (ECONNREFUSED)",
        "data": {}
    }

    res = worker._process_raw_tool_result("nmap", "port_scanning", "example.com", raw_res)
    assert res.status == ToolExecutionStatus.FAILED
    assert "TOOL_FAILED" in res.stdout or "Error" in res.stdout
