"""Phase 2.2 — consent-gated auto-pivot engine."""
from __future__ import annotations

from core.exploitation.pivot_engine import (
    PivotEngine,
    ServiceProbe,
    classify_service,
)
from core.security.consent import ExploitConsentManager


def _sim_network():
    """host 10.0.0.5: redis (unauth) + a Grafana login panel; everything else closed."""
    services = {
        ("10.0.0.5", 6379): ServiceProbe("10.0.0.5", 6379, open=True, service="redis",
                                         banner="redis_version:6.2", status=0, body=""),
        ("10.0.0.5", 8080): ServiceProbe("10.0.0.5", 8080, open=True, service="http-alt",
                                         banner="", status=200, body="<html>Grafana Login dashboard</html>"),
    }

    calls = []

    def prober(host, port):
        calls.append((host, port))
        return services.get((host, port), ServiceProbe(host, port, open=False))

    return prober, calls


def test_classify_unauthenticated_datastore():
    probe = ServiceProbe("h", 6379, open=True, service="redis", status=0)
    tags, sev = classify_service(probe)
    assert "sensitive_datastore" in tags
    assert "unauthenticated_datastore" in tags
    assert sev == "critical"


def test_classify_admin_panel_and_api():
    tags, sev = classify_service(ServiceProbe("h", 8080, open=True, body="Admin Dashboard login"))
    assert "admin_panel" in tags and sev == "high"
    tags2, _ = classify_service(ServiceProbe("h", 8000, open=True, body='{"swagger":"2.0","paths":{}}'))
    assert "unauthenticated_api" in tags2


async def test_pivot_blocked_without_consent_sends_no_probes():
    prober, calls = _sim_network()
    cm = ExploitConsentManager()
    cm.set_prompt(lambda text: "no")   # decline

    engine = PivotEngine(prober=prober, consent=cm)
    result = await engine.pivot(["10.0.0.5"])

    assert result.authorized is False
    assert result.services == []
    assert calls == [], "no probe may be sent when consent is declined"


async def test_pivot_discovers_services_when_approved():
    prober, calls = _sim_network()
    cm = ExploitConsentManager()
    cm.set_auto_approve(True)

    engine = PivotEngine(prober=prober, consent=cm)
    result = await engine.pivot(["10.0.0.5"])

    assert result.authorized is True
    assert calls, "prober must run once approved"
    services = {(s.host, s.port): s for s in result.services}
    assert ("10.0.0.5", 6379) in services
    assert "unauthenticated_datastore" in services[("10.0.0.5", 6379)].tags
    assert ("10.0.0.5", 8080) in services
    assert "admin_panel" in services[("10.0.0.5", 8080)].tags
    assert result.graph["10.0.0.5"] == [6379, 8080] or set(result.graph["10.0.0.5"]) == {6379, 8080}


async def test_pivot_no_hosts():
    prober, calls = _sim_network()
    engine = PivotEngine(prober=prober, consent=ExploitConsentManager())
    result = await engine.pivot([])
    assert result.authorized is False and calls == []


async def test_pivot_fails_closed_on_consent_error():
    prober, calls = _sim_network()

    class _BoomConsent:
        async def confirm(self, briefing):
            raise RuntimeError("consent subsystem down")

    engine = PivotEngine(prober=prober, consent=_BoomConsent())
    result = await engine.pivot(["10.0.0.5"])
    assert result.authorized is False
    assert calls == [], "must fail closed and not probe if consent errors"
