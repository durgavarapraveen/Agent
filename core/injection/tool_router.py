from typing import List, Dict, Any
from core.injection.models import InjectionTest

class InjectionToolRouter:
    @staticmethod
    def select_tools(test: InjectionTest) -> List[str]:
        # Maps an InjectionTest to a list of applicable tools (from Phase 7 adapters)
        tool_map = {
            "sqli": ["sqlmap", "nuclei", "custom_mutator"],
            "xss_reflected": ["dalfox", "nuclei", "browser", "custom_mutator"],
            "xss_stored": ["dalfox", "nuclei", "browser", "custom_mutator"],
            "xss_dom": ["browser", "custom_mutator"],
            "ssti": ["nuclei", "custom_mutator"],
            "command": ["custom_mutator", "nuclei"],
            "path_traversal": ["nuclei", "custom_mutator"]
        }
        return tool_map.get(test.test_type, ["custom_mutator"])
