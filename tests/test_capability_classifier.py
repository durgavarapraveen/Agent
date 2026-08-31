from core.common.normalizer import PlannerResponseNormalizer
from core.common.schemas import CapabilityType

def test_objective_capability_inference():
    # 1. Subdomain and DNS discovery
    cap1 = PlannerResponseNormalizer._infer_capability(
        "Discover subdomains and resolve IP addresses for mampg.org, ", {}
    )
    assert cap1 == CapabilityType.DNS_ENUMERATION

    cap2 = PlannerResponseNormalizer._infer_capability(
        "Enumerate all subdomains and DNS records for target.com", {}
    )
    assert cap2 == CapabilityType.DNS_ENUMERATION

    # 2. Port scanning
    cap3 = PlannerResponseNormalizer._infer_capability(
        "Scan open TCP ports on host 192.168.1.1", {}
    )
    assert cap3 == CapabilityType.PORT_SCANNING

    # 3. Technology fingerprinting
    cap4 = PlannerResponseNormalizer._infer_capability(
        "Detect technology stack and CMS version on https://example.com", {}
    )
    assert cap4 == CapabilityType.TECHNOLOGY_FINGERPRINTING

    # 4. Vulnerability scanning
    cap5 = PlannerResponseNormalizer._infer_capability(
        "Run nuclei templates and test for SQL injection and XSS", {}
    )
    assert cap5 == CapabilityType.VULNERABILITY_SCANNING

    # 5. Explicit capability priority
    cap6 = PlannerResponseNormalizer._infer_capability(
        "Generic probe", {"capability": "port_scanning"}
    )
    assert cap6 == CapabilityType.PORT_SCANNING
