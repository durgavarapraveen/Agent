"""P1.12 (endpoint origin/synthetic), P1.13 (finding confidence),
P1.14 (root-cause endpoint grouping)."""
import pytest

from core.memory.shared_context import SharedContextV2 as SharedContext
from core.analysis.finding_confidence import classify


def _ctx():
    return SharedContext("https://example.com", {"domains": ["example.com"]})


# ---- P1.12 -----------------------------------------------------------------

def test_synthetic_endpoints_diverted():
    ctx = _ctx()
    ctx.add_endpoints([
        {"url": "https://example.com/real", "method": "GET"},
        {"url": "https://example.com/__spa_detect_abc", "method": "GET"},
        {"url": "https://example.com/this-path-does-not-exist-98765", "method": "GET"},
    ], source="crawl")
    urls = [ctx._endpoint_url(e) for e in ctx.get_endpoints()]
    assert any("/real" in u for u in urls)
    assert not any("spa_detect" in u for u in urls)
    assert not any("does-not-exist" in u for u in urls)
    assert len(ctx.synthetic_endpoints) == 2


def test_endpoint_origin_stamped():
    ctx = _ctx()
    ep = {"url": "https://example.com/api/x", "method": "GET"}
    ctx.add_endpoints([ep], source="request_capture")
    assert ep["origin"] == "OBSERVED"
    ep2 = {"url": "https://example.com/api/y", "method": "GET"}
    ctx.add_endpoints([ep2], source="nuclei")
    assert ep2["origin"] == "TOOL_DERIVED"


# ---- P1.13 -----------------------------------------------------------------

def test_500_only_is_inconclusive_not_proof():
    v = {"type": "PROTOTYPE_POLLUTION", "confirmed": True,
         "proof": "POST /x -> HTTP 500", "severity": "HIGH"}
    assert classify(v) == "INCONCLUSIVE"


def test_real_bypass_is_confirmed():
    v = {"type": "AUTH_BYPASS", "confirmed": True,
         "proof": "POST /change-password -> HTTP 200 (password changed, bypass)",
         "severity": "CRITICAL"}
    assert classify(v) == "CONFIRMED"


def test_inconclusive_finding_not_mirrored_to_exploits():
    ctx = _ctx()
    ctx.add_vulnerability({"type": "STORED_XSS", "confirmed": True,
                           "title": "xss 500", "location": "https://example.com/c",
                           "proof": "submit -> HTTP 500", "severity": "HIGH"})
    assert ctx.vulnerabilities[-1]["confidence_label"] == "INCONCLUSIVE"
    assert ctx.exploit_results == []      # a 500 is not an exploit row


def test_confirmed_finding_mirrored():
    ctx = _ctx()
    ctx.add_vulnerability({"type": "IDOR", "confirmed": True, "title": "idor",
                           "location": "https://example.com/api/users/2",
                           "proof": "GET /api/users/2 -> HTTP 200 another user record",
                           "severity": "HIGH"})
    assert ctx.vulnerabilities[-1]["confidence_label"] == "CONFIRMED"
    assert len(ctx.exploit_results) == 1


# ---- P1.14 -----------------------------------------------------------------

def test_host_level_dedup_preserves_affected_endpoints():
    ctx = _ctx()
    for path in ("/", "/ftp/", "/api-docs/"):
        ctx.add_vulnerability({"type": "MISSING_HEADER", "title": "Missing CSP header",
                               "location": f"https://example.com{path}", "severity": "LOW"})
    csp = [v for v in ctx.vulnerabilities if v.get("type") == "MISSING_HEADER"]
    assert len(csp) == 1                                  # one root finding
    aff = csp[0].get("affected_endpoints", [])
    assert "https://example.com/ftp/" in aff and "https://example.com/api-docs/" in aff


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
