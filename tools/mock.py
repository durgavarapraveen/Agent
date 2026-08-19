from tools.base import Tool, ToolInputSchema, ToolOutputSchema, ToolPermission
from typing import Any, Dict
import httpx
import logging
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class MockReconTool(Tool):
    """Real reconnaissance tool with actual HTTP scanning."""
    
    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={"target": "str"},
            optional_params={"depth": "str"}
        )
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="Reconnaissance results"
        )
        super().__init__(
            name="mock_recon",
            description="Real reconnaissance tool for web targets",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE]
        )
    
    async def execute(self, **params) -> Dict[str, Any]:
        target = params.get("target", "unknown")
        technologies = []
        headers_found = {}
        
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                response = await client.get(target, follow_redirects=True)
                
                headers_found = dict(response.headers)
                content = response.text
                
                # Detect technologies from headers and content
                tech_patterns = {
                    "Flask": r"(Flask|werkzeug)",
                    "Django": r"(Django|django)",
                    "Express": r"(express|Express)",
                    "React": r"(react|React)",
                    "Vue": r"(vue|Vue)",
                    "Angular": r"(angular|Angular)",
                    "jQuery": r"(jquery|jQuery|\.js)",
                    "Bootstrap": r"(bootstrap|Bootstrap)",
                    "nginx": r"nginx",
                    "Apache": r"Apache",
                    "Node.js": r"(Node|node\.js)",
                    "Python": r"(Python|python)",
                    "PHP": r"PHP",
                    "Docker": r"(docker|Docker)",
                }
                
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, content + str(headers_found), re.IGNORECASE):
                        technologies.append(tech)
                
                parsed = urlparse(target)
                domain = parsed.netloc
                
                return {
                    "status": "success",
                    "target": target,
                    "discoveries": {
                        "domains": [domain],
                        "ips": [],
                        "ports": [443 if parsed.scheme == "https" else 80],
                        "services": ["HTTPS" if parsed.scheme == "https" else "HTTP"],
                        "technologies": list(set(technologies)) or ["Unknown"],
                        "status_code": response.status_code,
                        "headers": headers_found
                    }
                }
        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            return {
                "status": "error",
                "target": target,
                "error": str(e),
                "discoveries": {
                    "domains": [],
                    "ips": [],
                    "ports": [],
                    "services": [],
                    "technologies": []
                }
            }

class MockAPIAnalysisTool(Tool):
    """Mock API analysis tool."""
    
    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={"api_url": "str"},
            optional_params={"auth_type": "str"}
        )
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="API analysis results"
        )
        super().__init__(
            name="mock_api_analysis",
            description="Mock API analysis tool for demo",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE]
        )
    
    async def execute(self, **params) -> Dict[str, Any]:
        api_url = params.get("api_url", "unknown")
        return {
            "status": "success",
            "api_url": api_url,
            "api_type": "REST",
            "endpoints": [
                {"path": "/api/users", "methods": ["GET", "POST"], "auth_required": True},
                {"path": "/api/users/{id}", "methods": ["GET", "PUT", "DELETE"], "auth_required": True},
                {"path": "/api/products", "methods": ["GET"], "auth_required": False}
            ],
            "authentication": {
                "type": "JWT",
                "location": "Authorization header",
                "scheme": "Bearer"
            }
        }

class MockSourceAnalysisTool(Tool):
    """Mock source code analysis tool."""
    
    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={"repository_path": "str"},
            optional_params={"language": "str"}
        )
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="Source analysis results"
        )
        super().__init__(
            name="mock_source_analysis",
            description="Mock source analysis tool for demo",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE]
        )
    
    async def execute(self, **params) -> Dict[str, Any]:
        repo_path = params.get("repository_path", "unknown")
        return {
            "status": "success",
            "repository": repo_path,
            "language": "Python",
            "framework": "Flask",
            "dependencies": {
                "flask": "2.0.1",
                "requests": "2.28.0",
                "sqlalchemy": "1.4.0"
            },
            "files_analyzed": 47,
            "potential_issues": [
                {
                    "type": "hardcoded_secret",
                    "file": "config.py",
                    "line": 12,
                    "severity": "HIGH"
                },
                {
                    "type": "sql_injection",
                    "file": "models.py",
                    "line": 45,
                    "severity": "CRITICAL"
                }
            ]
        }

class MockValidationTool(Tool):
    """Mock validation tool."""
    
    def __init__(self):
        input_schema = ToolInputSchema(
            required_params={"finding_id": "str"},
            optional_params={"method": "str"}
        )
        output_schema = ToolOutputSchema(
            return_type="dict",
            description="Validation result"
        )
        super().__init__(
            name="mock_validation",
            description="Mock validation tool for demo",
            input_schema=input_schema,
            output_schema=output_schema,
            permissions=[ToolPermission.PASSIVE, ToolPermission.SAFE_ACTIVE]
        )
    
    async def execute(self, **params) -> Dict[str, Any]:
        finding_id = params.get("finding_id", "unknown")
        return {
            "status": "success",
            "finding_id": finding_id,
            "validation_result": "CONFIRMED",
            "confidence": 0.95,
            "evidence": {
                "response_headers": {
                    "X-Frame-Options": "MISSING",
                    "X-Content-Type-Options": "MISSING"
                }
            }
        }