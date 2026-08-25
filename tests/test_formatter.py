"""
Unit tests for ToolResultFormatter.
Tests 5 tool compression rules and 3-sentence formatting.
"""

import pytest
from core.result_formatter import ToolResultFormatter


def test_subfinder_compression():
    raw_subdomains = [f"sub{i}.example.com" for i in range(25)]
    data = {"subdomains": raw_subdomains}
    
    assert ToolResultFormatter.should_compress("subfinder", raw_subdomains) is True
    compressed = ToolResultFormatter.compress_tool_data("subfinder", data)
    assert len(compressed["subdomains"]) == 5
    assert compressed["subdomains_truncated_count"] == 20

    summary = ToolResultFormatter.format_success_result("subfinder", compressed)
    assert "STATUS: SUCCESS for tool 'subfinder'" in summary
    assert "KEY FINDING:" in summary
    assert "RECOMMENDATION:" in summary


def test_nmap_compression():
    raw_ports = [{"port": p, "service": "http", "state": "open"} for p in range(1, 50)]
    data = {"ports": raw_ports}

    assert ToolResultFormatter.should_compress("nmap", raw_ports) is True
    compressed = ToolResultFormatter.compress_tool_data("nmap", data)
    assert len(compressed["ports"]) == 20
    assert compressed["ports_truncated_count"] == 29


def test_sslscan_compression():
    data = {
        "protocols": ["TLSv1.2", "TLSv1.3"],
        "weak_ciphers": ["RC4-SHA"],
        "vulnerabilities": ["Heartbleed: NOT VULNERABLE"],
        "all_ciphers_raw": "A" * 5000
    }

    assert ToolResultFormatter.should_compress("sslscan", data) is True
    compressed = ToolResultFormatter.compress_tool_data("sslscan", data)
    assert "all_ciphers_raw" not in compressed
    assert compressed["protocols"] == ["TLSv1.2", "TLSv1.3"]


def test_httpx_compression():
    raw_endpoints = [f"https://example.com/api/v{i}" for i in range(30)]
    data = {"endpoints": raw_endpoints}

    assert ToolResultFormatter.should_compress("httpx", raw_endpoints) is True
    compressed = ToolResultFormatter.compress_tool_data("httpx", data)
    assert len(compressed["endpoints"]) == 10
    assert compressed["endpoints_truncated_count"] == 20


def test_katana_compression():
    raw_endpoints = [f"https://example.com/path/{i}" for i in range(100)]
    data = {"endpoints": raw_endpoints}

    assert ToolResultFormatter.should_compress("katana", raw_endpoints) is True
    compressed = ToolResultFormatter.compress_tool_data("katana", data)
    assert len(compressed["endpoints"]) == 50


def test_failure_formatting():
    fmt = ToolResultFormatter.format_failure_result("nmap", "TIMEOUT", "Connection timed out after 30s")
    assert "STATUS: FAILED for tool 'nmap'" in fmt
    assert "ERROR REASON:" in fmt
    assert "NEXT ACTION:" in fmt


def test_duplicate_formatting():
    fmt = ToolResultFormatter.format_duplicate_result("subfinder", "TASK-1234")
    assert "STATUS: DEDUPLICATED for tool 'subfinder'" in fmt
    assert "TASK-1234" in fmt
