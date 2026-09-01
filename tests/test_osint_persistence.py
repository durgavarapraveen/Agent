from core.memory.shared_context import SharedContext
from core.intelligence.osint_engine import Employee
from core.intelligence.osint_integration import OSINTOrchestrator
from core.reporting import EnterpriseReporter

def test_osint_employee_storage_and_harvesting():
    ctx = SharedContext("https://example.com")
    
    # 1. Simulate discovery of 6 employees
    employees = [
        Employee(name=f"User {i}", email=f"user{i}@example.com", role="Engineer", 
                 domain="example.com", source="company_website", confidence=0.8, 
                 discovered_date="2026-08-29T10:00:00")
        for i in range(1, 7)
    ]
    
    # 2. Update SharedContext
    ctx.update("discovered_employees", employees)
    
    # Verify count and synchronization into harvested_creds
    assert len(ctx.discovered_employees) == 6
    assert len(ctx.harvested_creds) == 6
    assert ctx.harvested_creds[0]["username"] == "user1@example.com"
    assert ctx.harvested_creds[0]["type"] == "employee_email"
    
    # 3. Verify to_dict() serialization
    d = ctx.to_dict()
    assert "discovered_employees" in d
    assert len(d["discovered_employees"]) == 6
    assert d["discovered_employees"][0]["email"] == "user1@example.com"
    
    # 4. Verify summary calculation in OSINTOrchestrator
    orchestrator = OSINTOrchestrator(ctx)
    summary = orchestrator.generate_osint_summary_report()
    assert summary["osint_summary"]["employees"]["total_employees"] == 6
    
    # 5. Verify HTML report inclusion
    reporter = EnterpriseReporter(ctx)
    html = reporter.build_html()
    assert "user1@example.com" in html
    assert "user6@example.com" in html
