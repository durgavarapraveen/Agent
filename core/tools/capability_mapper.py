from typing import List

class CapabilityMapper:
    def __init__(self):
        self.mapping = {
            "port_scanning": ["masscan", "nmap"],
            "sql_injection": ["sqlmap", "nuclei", "dalfox"],
            "xss": ["dalfox", "nuclei"],
            "idor": ["burp", "nuclei"],
            "cve_scanning": ["nuclei", "nmap"]
        }

    def get_tools_for_capability(self, capability: str) -> List[str]:
        return self.mapping.get(capability, [])
