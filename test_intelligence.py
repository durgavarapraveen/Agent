"""
Test Phase 1: Intelligence System
Run: python test_intelligence.py

Tests:
  1. NVD CVE search
  2. GitHub exploit search
  3. MITRE technique lookup
  4. Knowledge base caching
  5. Intelligence manager (combined)
  6. Tool installer check
"""

import asyncio
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.intelligence_fetcher import IntelligenceFetcher
from core.knowledge_base import KnowledgeBase
from core.tool_installer import ToolInstaller


async def test_nvd():
    """Test NVD CVE search."""
    print("\n" + "=" * 60)
    print("TEST 1: NVD CVE Search")
    print("=" * 60)

    fetcher = IntelligenceFetcher()

    # Search for Apache vulnerabilities
    cves = await fetcher.search_nvd("apache", "2.4.49", max_results=5)

    if cves:
        print(f"✓ Found {len(cves)} CVEs for Apache 2.4.49")
        for cve in cves[:3]:
            print(f"  - {cve['cve_id']} (CVSS {cve['cvss']}, {cve['severity']})")
            print(f"    {cve['description'][:100]}...")
        return True
    else:
        print("✗ No CVEs found (might be rate limited, try again in 30s)")
        return False


async def test_github():
    """Test GitHub exploit search."""
    print("\n" + "=" * 60)
    print("TEST 2: GitHub Exploit Search")
    print("=" * 60)

    fetcher = IntelligenceFetcher()

    # Search for Log4j exploits
    exploits = await fetcher.search_github_exploits(
        cve_id="CVE-2021-44228", max_results=3
    )

    if exploits:
        print(f"✓ Found {len(exploits)} exploit repos for CVE-2021-44228 (Log4Shell)")
        for exp in exploits:
            print(f"  - {exp['name']} ({exp['stars']} stars, reliability {exp['reliability']:.0%})")
            print(f"    {exp['url']}")
        return True
    else:
        print("✗ No exploits found (might be rate limited)")
        return False


async def test_mitre():
    """Test MITRE ATT&CK lookup."""
    print("\n" + "=" * 60)
    print("TEST 3: MITRE ATT&CK Lookup")
    print("=" * 60)

    fetcher = IntelligenceFetcher()

    # Lookup specific technique
    techniques = await fetcher.search_mitre(technique_id="T1190")

    if techniques:
        tech = techniques[0]
        print(f"✓ Found technique: {tech['id']} - {tech['name']}")
        print(f"  Tactic: {tech['tactic']}")
        print(f"  Mitigations: {', '.join(tech.get('mitigations', [])[:3])}")
        return True
    else:
        print("✗ MITRE lookup failed")
        return False


async def test_mitre_vuln_mapping():
    """Test MITRE vulnerability type mapping."""
    print("\n" + "=" * 60)
    print("TEST 4: MITRE Vuln Type Mapping")
    print("=" * 60)

    fetcher = IntelligenceFetcher()

    for vuln_type in ["sqli", "xss", "rce", "privilege_escalation"]:
        techniques = await fetcher.search_mitre_for_vuln(vuln_type)
        if techniques:
            ids = ", ".join(t["id"] for t in techniques)
            print(f"  ✓ {vuln_type} → {ids}")
        else:
            print(f"  ✗ {vuln_type} → no mapping")

    return True


async def test_cache():
    """Test knowledge base caching."""
    print("\n" + "=" * 60)
    print("TEST 5: Knowledge Base Cache")
    print("=" * 60)

    # Use temp database
    kb = KnowledgeBase(db_path="test_kb.db")

    # Cache some CVEs
    test_cves = [
        {
            "cve_id": "CVE-2021-44228",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "Apache Log4j2 RCE",
            "cwes": ["CWE-917"],
            "references": [{"url": "https://example.com", "source": "test", "tags": []}],
            "published": "2021-12-10",
            "modified": "2023-01-01",
            "product": "log4j",
            "version": "2.14.1",
        }
    ]

    kb.cache_cves(test_cves)
    print("  ✓ Cached 1 CVE")

    # Retrieve
    cached = kb.get_cached_cves("log4j", "2.14.1")
    if cached and cached[0]["cve_id"] == "CVE-2021-44228":
        print(f"  ✓ Cache hit: {cached[0]['cve_id']} (CVSS {cached[0]['cvss']})")
    else:
        print("  ✗ Cache miss")
        return False

    # Test cache miss
    miss = kb.get_cached_cves("nonexistent", "0.0.0")
    if miss is None:
        print("  ✓ Cache miss returns None (correct)")
    else:
        print("  ✗ Cache miss should return None")

    # Stats
    stats = kb.get_stats()
    print(f"  Stats: {stats}")

    # Decision log
    kb.log_decision("test", "Testing intelligence", "test context", "success")
    decisions = kb.get_decisions(phase="test")
    print(f"  ✓ Decision log: {len(decisions)} entries")

    # Cleanup
    kb.clear_all()
    os.remove("test_kb.db")
    print("  ✓ Cleanup complete")

    return True


async def test_service_parser():
    """Test service version extraction."""
    print("\n" + "=" * 60)
    print("TEST 6: Service Version Extraction")
    print("=" * 60)

    fetcher = IntelligenceFetcher()

    test_banners = [
        ("Apache/2.4.49", ("apache", "2.4.49")),
        ("OpenSSH 8.2p1", ("openssh", "8.2")),
        ("nginx/1.18.0", ("nginx", "1.18.0")),
        ("MySQL version 8.0.26", ("mysql", "8.0.26")),
    ]

    all_pass = True
    for banner, expected in test_banners:
        result = fetcher.extract_service_version(banner)
        if result == expected:
            print(f"  ✓ '{banner}' → {result}")
        else:
            print(f"  ✗ '{banner}' → {result} (expected {expected})")
            all_pass = False

    return all_pass


def test_tool_installer():
    """Test tool installer (listing only, no actual install)."""
    print("\n" + "=" * 60)
    print("TEST 7: Tool Installer")
    print("=" * 60)

    installer = ToolInstaller()

    available = installer.list_available()
    print(f"  ✓ {len(available)} tools in install registry")
    print(f"  Sample: {', '.join(available[:10])}")

    return True


async def main():
    print("=" * 60)
    print("PHASE 1 INTELLIGENCE SYSTEM - INTEGRATION TESTS")
    print("=" * 60)

    results = {}

    results["NVD Search"] = await test_nvd()
    results["GitHub Exploits"] = await test_github()
    results["MITRE Lookup"] = await test_mitre()
    results["MITRE Vuln Map"] = await test_mitre_vuln_mapping()
    results["Cache"] = await test_cache()
    results["Service Parser"] = await test_service_parser()
    results["Tool Installer"] = test_tool_installer()

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test, ok in results.items():
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {status}: {test}")

    print(f"\n{passed}/{total} tests passed")

    if passed == total:
        print("\n✓ ALL TESTS PASSED - Phase 1 Intelligence System is working!")
    else:
        print("\n⚠ Some tests failed (API rate limits may cause failures, retry in 30s)")


if __name__ == "__main__":
    asyncio.run(main())