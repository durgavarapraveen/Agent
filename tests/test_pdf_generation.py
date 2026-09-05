import os
from core.memory.shared_context import SharedContextV2 as SharedContext
from core.reporting import EnterpriseReporter

def test_enterprise_report_pdf_generation():
    ctx = SharedContext("https://example.com")
    ctx.add_subdomains(["api.example.com", "dev.example.com"])
    ctx.add_ports("example.com", [{"port": 80, "service": "http", "state": "open"}])
    
    reporter = EnterpriseReporter(ctx)
    res = reporter.generate(stem="test_report_pdf")
    
    assert "html" in res
    assert os.path.exists(res["html"])
    assert "pdf" in res
    assert os.path.exists(res["pdf"])
    assert os.path.getsize(res["pdf"]) > 0
