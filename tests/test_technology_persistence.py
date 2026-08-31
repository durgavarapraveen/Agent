from core.memory.shared_context import SharedContext
from core.exploitation.request_capture import RequestCapturer, CaptureResult, CapturedRequest
from core.orchestration.capability_worker import CapabilityWorker
from core.tools.tool_registry import ToolRegistry

def test_request_capture_technology_extraction_and_persistence():
    ctx = SharedContext("https://mampg.org")
    capturer = RequestCapturer()
    
    # Simulate captured requests with Next.js, Webpack, static CSS, CDN, server headers
    reqs = [
        CapturedRequest(
            method="GET",
            url="https://mampg.org/_next/static/chunks/webpack-123.js",
            resource_type="script",
            is_preflight=False,
            status=200,
            headers={"Server": "cloudflare", "X-Powered-By": "Next.js"},
            post_data=""
        ),
        CapturedRequest(
            method="GET",
            url="https://mampg.org/static/css/main.css",
            resource_type="stylesheet",
            is_preflight=False,
            status=200,
            headers={},
            post_data=""
        ),
        CapturedRequest(
            method="GET",
            url="https://ccms-api.sahasra.io/api/v1/content",
            resource_type="fetch",
            is_preflight=False,
            status=200,
            headers={},
            post_data=""
        )
    ]
    
    capture_res = CaptureResult("https://mampg.org", ["https://mampg.org"], reqs)
    capturer.store(capture_res, ctx)
    
    # Verify technologies in SharedContext
    assert "mampg.org" in ctx.technologies
    techs = ctx.technologies["mampg.org"]
    assert "Next.js" in techs
    assert "Webpack" in techs
    assert "CSS/Stylesheets" in techs
    assert "Server:cloudflare" in techs
    assert "Powered-By:Next.js" in techs
    assert "External/CDN:ccms-api.sahasra.io" in techs

    # Verify serialization
    d = ctx.to_dict()
    assert "technologies" in d
    assert "mampg.org" in d["technologies"]
    assert len(d["technologies"]["mampg.org"]) >= 5

def test_capability_worker_technology_recording():
    ctx = SharedContext("https://example.com")
    worker = CapabilityWorker("agent-001", ToolRegistry(), ctx)
    data = {
        "technologies": ["React", "Express", "Node.js"]
    }
    worker._record_extracted_data(data, "whatweb", "https://example.com")
    assert "example.com" in ctx.technologies
    assert "React" in ctx.technologies["example.com"]
    assert "Node.js" in ctx.technologies["example.com"]
