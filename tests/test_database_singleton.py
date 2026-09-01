from core.intelligence.osint_engine import OSINTDatabase
from core.intelligence.threat_intel import ThreatIntelDatabase
from core.intelligence.subdomain_enum import SubdomainDatabase

def test_database_singleton_instances():
    # 1. OSINTDatabase
    db1 = OSINTDatabase("data/db/osint_findings.sqlite")
    db2 = OSINTDatabase("data/db/osint_findings.sqlite")
    assert db1 is db2

    # 2. ThreatIntelDatabase
    tdb1 = ThreatIntelDatabase("data/db/threat_intel.sqlite")
    tdb2 = ThreatIntelDatabase("data/db/threat_intel.sqlite")
    assert tdb1 is tdb2

    # 3. SubdomainDatabase
    sdb1 = SubdomainDatabase("data/db/subdomains.sqlite")
    sdb2 = SubdomainDatabase("data/db/subdomains.sqlite")
    assert sdb1 is sdb2

    # 4. In-memory databases are isolated when requested
    mem1 = OSINTDatabase(":memory:")
    mem2 = OSINTDatabase(":memory:")
    assert mem1 is not mem2
