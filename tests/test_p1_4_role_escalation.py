"""Phase 1.4 — role escalation & BOLA sequence finder."""
from __future__ import annotations

from core.execution.executors.role_escalation import (
    ResourceCrud,
    RoleEscalationAnalyzer,
    looks_like_admin_endpoint,
)
from core.exploitation.workflow_interceptor import ReplayResponse

IDENTITIES = {"user_a": "standard", "user_b": "standard", "admin": "administrator"}


def _resource():
    return ResourceCrud(
        name="/api/orders/1",
        create={"method": "POST", "url": "https://app.test/api/orders", "post_data": "{}"},
        read={"method": "GET", "url": "https://app.test/api/orders/1"},
        update={"method": "PUT", "url": "https://app.test/api/orders/1", "post_data": "{}"},
        delete={"method": "DELETE", "url": "https://app.test/api/orders/1"},
    )


def test_bola_and_auth_bypass_on_vulnerable_app():
    analyzer = RoleEscalationAnalyzer(lambda req, iid: ReplayResponse(200), IDENTITIES)
    findings = analyzer.analyze_resource(_resource())
    tests = {f.test for f in findings}
    assert "bola" in tests          # peer user_b can access user_a's resource
    assert "auth_bypass" in tests   # unauthenticated access succeeds
    # update/delete BOLA are critical
    crit = [f for f in findings if f.test == "bola" and f.operation in ("update", "delete")]
    assert crit and all(f.severity == "critical" for f in crit)


def test_secure_app_no_findings():
    # Only the owner (user_a) is authorized; everyone else and unauth get 403.
    def secure(req, iid):
        return ReplayResponse(200) if iid == "user_a" else ReplayResponse(403)

    analyzer = RoleEscalationAnalyzer(secure, IDENTITIES)
    assert analyzer.analyze_resource(_resource()) == []


def test_vertical_escalation():
    admin_reqs = [{"method": "GET", "url": "https://app.test/admin/users"}]

    vuln = RoleEscalationAnalyzer(lambda req, iid: ReplayResponse(200), IDENTITIES)
    vfind = vuln.test_vertical(admin_reqs)
    assert vfind and all(f.test == "vertical_escalation" for f in vfind)
    # admin identity is not a low-priv actor, so only standard users are flagged
    assert {f.actor for f in vfind} == {"user_a", "user_b"}

    def secure(req, iid):
        return ReplayResponse(200) if iid == "admin" else ReplayResponse(403)

    assert RoleEscalationAnalyzer(secure, IDENTITIES).test_vertical(admin_reqs) == []


def test_looks_like_admin_endpoint():
    assert looks_like_admin_endpoint("https://app.test/admin/users")
    assert looks_like_admin_endpoint("https://app.test/internal/config")
    assert not looks_like_admin_endpoint("https://app.test/api/products")


def test_executor_end_to_end(monkeypatch):
    from core.domain.experiment import SecurityExperiment
    from core.execution.executors.role_escalation import RoleEscalationExecutor

    ex = RoleEscalationExecutor()
    # Vulnerable app: everything returns 200 regardless of identity.
    monkeypatch.setattr(ex, "_probe", lambda url, method="GET", headers=None, data=None: (200, "ok", {}))

    exp = SecurityExperiment(
        hypothesis_id="h", endpoint_id="https://app.test", capability="role_escalation",
        input_parameters={
            "url": "https://app.test",
            "identities": [
                {"id": "user_a", "role": "standard", "token": "ta"},
                {"id": "user_b", "role": "standard", "token": "tb"},
                {"id": "admin", "role": "administrator", "token": "tadmin"},
            ],
            "endpoints": [{"url": "https://app.test/admin/users"},
                          {"url": "https://app.test/api/orders/1"}],
            "crud_resources": [{
                "name": "order",
                "create": {"method": "POST", "url": "https://app.test/api/orders", "post_data": "{}"},
                "read": {"method": "GET", "url": "https://app.test/api/orders/1"},
                "update": {"method": "PUT", "url": "https://app.test/api/orders/1", "post_data": "{}"},
                "delete": {"method": "DELETE", "url": "https://app.test/api/orders/1"},
            }],
        },
    )
    result = ex.execute(exp)
    findings = result.evidence.get("escalation_findings", [])
    tests = {f["test"] for f in findings}
    assert "bola" in tests
    assert "vertical_escalation" in tests
