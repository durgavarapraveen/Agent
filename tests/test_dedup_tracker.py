"""
Unit and integration tests for core/dedup_tracker.py.
Tests 3x subfinder runs (first=all, second=delta/no new, third=all duplicate).
"""

import os
import tempfile
import pytest
from core.dedup_tracker import DeduplicationTracker


@pytest.fixture
def dedup_tracker():
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    tracker = DeduplicationTracker(db_path=tmp.name)
    yield tracker
    if os.path.exists(tmp.name):
        os.unlink(tmp.name)


def test_signature_generation(dedup_tracker):
    sig1 = dedup_tracker.generate_signature("subfinder", "domains", "sub1.example.com")
    sig2 = dedup_tracker.generate_signature("subfinder", "domains", "sub1.example.com")
    sig3 = dedup_tracker.generate_signature("subfinder", "domains", "sub2.example.com")
    
    assert sig1 == sig2
    assert sig1 != sig3
    assert sig1.startswith("subfinder:domains:")


def test_3x_subfinder_deduplication_flow(dedup_tracker):
    target = "example.com"
    run1_data = ["sub1.example.com", "sub2.example.com", "sub3.example.com"]
    run2_data = ["sub1.example.com", "sub2.example.com", "sub3.example.com", "sub4.example.com"]
    run3_data = ["sub1.example.com", "sub2.example.com", "sub3.example.com", "sub4.example.com"]

    # --- Run 1: First run sends all findings ---
    delta1 = dedup_tracker.get_delta("subfinder", "domains", run1_data, task_id="AGENT-001")
    assert delta1["total_count"] == 3
    assert delta1["new_count"] == 3
    assert delta1["known_count"] == 0
    assert "New findings: +3" in delta1["formatted_summary"]

    # --- Run 2: Second run detects 1 new item (sub4) ---
    delta2 = dedup_tracker.get_delta("subfinder", "domains", run2_data, task_id="AGENT-002")
    assert delta2["total_count"] == 4
    assert delta2["new_count"] == 1
    assert delta2["known_count"] == 3
    assert delta2["new_items"] == ["sub4.example.com"]
    assert "New findings: +1 (sub4.example.com)" in delta2["formatted_summary"]

    # --- Run 3: Third run detects 0 new items ---
    delta3 = dedup_tracker.get_delta("subfinder", "domains", run3_data, task_id="AGENT-003")
    assert delta3["total_count"] == 4
    assert delta3["new_count"] == 0
    assert delta3["known_count"] == 4
    assert "New findings: +0" in delta3["formatted_summary"]


def test_cache_clearing(dedup_tracker):
    dedup_tracker.register_finding("nmap", "ports", {"port": 80}, task_id="AGENT-001")
    assert dedup_tracker.is_duplicate("nmap", "ports", {"port": 80}) is True

    # Purge cache older than -1 hours (force purge all)
    deleted = dedup_tracker.clear_cache(hours=-1)
    assert deleted >= 1
    assert dedup_tracker.is_duplicate("nmap", "ports", {"port": 80}) is False


def test_subdomain_dedup_key_isolation(dedup_tracker):
    key1 = dedup_tracker.generate_task_key("port_scanning", "millisecond.speshway.com", "80")
    key2 = dedup_tracker.generate_task_key("port_scanning", "www.speshway.com", "80")
    key3 = dedup_tracker.generate_task_key("port_scanning", "speshway.com", "80")

    assert key1 == "port_scanning:millisecond.speshway.com:80"
    assert key2 == "port_scanning:www.speshway.com:80"
    assert key3 == "port_scanning:speshway.com:80"

    assert key1 != key2
    assert key1 != key3
    assert key2 != key3


def test_subdomain_finding_isolation(dedup_tracker):
    sub1 = "millisecond.speshway.com"
    sub2 = "www.speshway.com"

    sig1 = dedup_tracker.generate_signature("spawner", "task_gravity", f"port_scanning:{sub1}:80")
    sig2 = dedup_tracker.generate_signature("spawner", "task_gravity", f"port_scanning:{sub2}:80")

    assert sig1 != sig2
    assert dedup_tracker.is_duplicate("spawner", "task_gravity", f"port_scanning:{sub1}:80") is False

    dedup_tracker.register_finding("spawner", "task_gravity", f"port_scanning:{sub1}:80")
    assert dedup_tracker.is_duplicate("spawner", "task_gravity", f"port_scanning:{sub1}:80") is True
    assert dedup_tracker.is_duplicate("spawner", "task_gravity", f"port_scanning:{sub2}:80") is False

