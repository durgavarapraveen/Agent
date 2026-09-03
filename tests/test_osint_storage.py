"""
Tests for OSINT Storage, Intelligence Engines, Database Persistence, and Reporting
"""

import pytest
from datetime import datetime

from core.intelligence.osint_engine import OSINTDatabase, Employee, LeakedCredential, DomainIntelligence
from core.intelligence.threat_intel import ThreatIntelDatabase, ThreatIndicator, ReputationScore
from core.intelligence.subdomain_enum import SubdomainDatabase, Subdomain, VirtualHost, CloudStorageBucket
from core.reporting import EnterpriseReporter
from core.memory.shared_context_v2 import SharedContextV2 as SharedContext
from core.common.schemas import CapabilityType


@pytest.fixture
def temp_dbs():
    osint_db = OSINTDatabase()
    threat_db = ThreatIntelDatabase()
    subdomain_db = SubdomainDatabase()

    yield osint_db, threat_db, subdomain_db


def test_osint_database_employee_and_cred_persistence(temp_dbs):
    osint_db, _, _ = temp_dbs

    emp = Employee(
        name="Alice Smith",
        email="alice.smith@example.com",
        role="DevOps Lead",
        domain="example.com",
        source="company_website",
        confidence=0.9,
        discovered_date=datetime.now().isoformat()
    )
    assert osint_db.save_employee(emp) is True

    retrieved_emps = osint_db.get_employees("example.com")
    assert len(retrieved_emps) == 1
    assert retrieved_emps[0].email == "alice.smith@example.com"
    assert retrieved_emps[0].name == "Alice Smith"
    assert osint_db.count_employees("example.com") == 1

    cred = LeakedCredential(
        username="admin",
        email="alice.smith@example.com",
        password="secretpassword123",
        service="github",
        found_in_repo="example/repo:.env",
        severity="critical",
        url="https://github.com/example/repo/blob/main/.env",
        discovered_date=datetime.now().isoformat()
    )
    assert osint_db.save_credential(cred) is True

    retrieved_creds = osint_db.get_credentials(severity="critical")
    assert len(retrieved_creds) == 1
    assert retrieved_creds[0].service == "github"
    assert retrieved_creds[0].url == "https://github.com/example/repo/blob/main/.env"
    assert retrieved_creds[0].password is None


def test_domain_intelligence_persistence(temp_dbs):
    osint_db, _, _ = temp_dbs

    intel = DomainIntelligence(
        domain="example.com",
        mx_records=["mail.example.com"],
        spf_policy="v=spf1 -all",
        dkim_enabled=True,
        dmarc_policy="p=reject",
        mail_server_versions={"mail.example.com": "Postfix 3.5"},
        ns_records=["ns1.example.com"],
        ip_ranges=["192.0.2.0/24"],
        discovered_date=datetime.now().isoformat()
    )
    assert osint_db.save_domain_intel(intel) is True


def test_threat_intel_database_persistence(temp_dbs):
    _, threat_db, _ = temp_dbs

    indicator = ThreatIndicator(
        type="ip",
        value="198.51.100.42",
        threat_type="botnet_c2",
        severity="critical",
        sources=["botnet_c2", "urlhaus"],
        first_seen=datetime.now().isoformat(),
        last_seen=datetime.now().isoformat(),
        description="Malicious C2 Server",
        confidence=0.98
    )
    assert threat_db.save_threat_indicator(indicator) is True

    retrieved = threat_db.get_threat_indicators_for_asset("198.51.100.42")
    assert len(retrieved) == 1
    assert retrieved[0].threat_type == "botnet_c2"

    criticals = threat_db.get_critical_threats()
    assert len(criticals) == 1

    score = ReputationScore(
        asset="198.51.100.42",
        overall_score=85.5,
        detection_engines=4,
        threat_types=["botnet_c2"],
        abuse_reports=12,
        first_flagged=datetime.now().isoformat(),
        last_flagged=datetime.now().isoformat(),
        whitelisted=False
    )
    assert threat_db.save_reputation_score(score) is True


def test_subdomain_database_persistence(temp_dbs):
    _, _, subdomain_db = temp_dbs

    sub = Subdomain(
        name="api.example.com",
        domain="example.com",
        ip_addresses=["192.0.2.10"],
        cname="api.example.com.cdn.cloudflare.net",
        cdn="cloudflare",
        cloud_storage=None,
        certificate_issuer="Let's Encrypt",
        certificate_not_before=datetime.now().isoformat(),
        certificate_not_after=datetime.now().isoformat(),
        status_code=200,
        title="API Portal",
        technologies=["Node.js", "Express"],
        source="crt.sh",
        confidence=0.95,
        discovered_date=datetime.now().isoformat()
    )
    assert subdomain_db.save_subdomain(sub) is True

    subdomains = subdomain_db.get_subdomains("example.com")
    assert len(subdomains) == 1
    assert subdomains[0].name == "api.example.com"
    assert subdomains[0].cdn == "cloudflare"
    assert subdomain_db.count_subdomains("example.com") == 1

    vhost = VirtualHost(
        host_header="internal-dev.example.com",
        target_ip="192.0.2.10",
        status_code=200,
        title="Internal Dev",
        server_header="nginx",
        technologies=["Python"],
        confidence=0.9,
        discovered_date=datetime.now().isoformat()
    )
    assert subdomain_db.save_virtual_host(vhost) is True

    bucket = CloudStorageBucket(
        bucket_name="example-assets",
        bucket_type="s3",
        target_domain="example.com",
        region="us-east-1",
        public=True,
        files_count=42,
        accessible_paths=["/public/logo.png"],
        discovered_date=datetime.now().isoformat()
    )
    assert subdomain_db.save_cloud_bucket(bucket) is True


def test_osint_capability_schemas():
    assert CapabilityType.EMPLOYEE_ENUMERATION.value == "employee_enumeration"
    assert CapabilityType.GITHUB_SCANNING.value == "github_scanning"
    assert CapabilityType.DNS_INTELLIGENCE.value == "dns_intelligence"
    assert CapabilityType.SUBDOMAIN_ENUMERATION.value == "subdomain_enumeration"
    assert CapabilityType.THREAT_INTELLIGENCE.value == "threat_intelligence"


def test_osint_report_integration(temp_dbs):
    ctx = SharedContext(target="https://example.com")
    ctx.update("discovered_employees", [
        Employee(
            name="Alice Smith",
            email="alice@example.com",
            role="Engineer",
            domain="example.com",
            source="linkedin",
            confidence=0.9,
            discovered_date=datetime.now().isoformat()
        )
    ])
    ctx.update("discovered_subdomains", [
        Subdomain(
            name="sub.example.com",
            domain="example.com",
            ip_addresses=["192.0.2.1"],
            cname=None,
            cdn="Cloudflare",
            cloud_storage=None,
            certificate_issuer="DigiCert",
            certificate_not_before=None,
            certificate_not_after=None,
            status_code=200,
            title="Sub",
            technologies=[],
            source="crt.sh",
            confidence=0.9,
            discovered_date=datetime.now().isoformat()
        )
    ])

    reporter = EnterpriseReporter(ctx)
    html_output = reporter.build_html("Executive Summary for test")
    
    assert "OSINT Reconnaissance Findings" in html_output
    assert "alice@example.com" in html_output
    assert "sub.example.com" in html_output
