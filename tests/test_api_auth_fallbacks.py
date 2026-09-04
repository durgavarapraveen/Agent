import asyncio
from core.intelligence.subdomain_enum import CertificateTransparencyScanner
from core.intelligence.osint_engine import GitHubScanner
from core.intelligence.threat_intel import AbuseChIntelligence, ThreatIntelDatabase
from core.intelligence.censys_client import CensysClient

def test_subdomain_scanner_multi_source_fallback():
    async def _test():
        scanner = CertificateTransparencyScanner()
        subs = await scanner.query_all_sources("example.com")
        assert isinstance(subs, list)
    asyncio.run(_test())

def test_github_scanner_fallback():
    async def _test():
        scanner = GitHubScanner()
        repos = await scanner.find_organization_repos("non_existent_org_xyz_123_456")
        assert isinstance(repos, list)
    asyncio.run(_test())

def test_threat_intel_feed_fallbacks():
    async def _test():
        db = ThreatIntelDatabase()
        intel = AbuseChIntelligence(db)
        phishing = await intel.query_phishing_army()
        assert isinstance(phishing, list)
        malware = await intel.query_malware_bazon()
        assert isinstance(malware, list)
    asyncio.run(_test())

def test_censys_unconfigured_handling():
    client = CensysClient(api_token="")
    assert client.is_configured is False
