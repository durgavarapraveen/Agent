from typing import List

class CapabilityMapper:
    """Thin adapter over the dynamic capability registry. The old hardcoded
    dict is kept as a local fallback, but lookups now consult the runtime
    registry so newly-registered/available tools are included."""

    def __init__(self):
        self.mapping = {
            "port_scanning": ["masscan", "nmap"],
            "sql_injection": ["sqlmap", "nuclei", "dalfox"],
            "xss": ["dalfox", "nuclei"],
            "idor": ["burp", "nuclei"],
            "cve_scanning": ["nuclei", "nmap"]
        }

    def get_tools_for_capability(self, capability: str) -> List[str]:
        try:
            from core.tools.dynamic_capability_registry import get_capability_registry
            tools = get_capability_registry().get_tools_for_capability(capability)
            if tools:
                return tools
        except Exception:
            pass
        return self.mapping.get(capability, [])
