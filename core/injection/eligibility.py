from typing import List, Dict, Any, Optional
from core.domain.endpoint import Endpoint
from core.domain.identity import Identity
from core.injection.models import InjectionTest
import uuid

class InjectionEligibilityChecker:
    @staticmethod
    def is_eligible(endpoint: Endpoint, parameter_name: str, content_type: str, identity: Optional[Identity]) -> List[InjectionTest]:
        applicable = []
        method_set = set(endpoint.method_set) if isinstance(endpoint.method_set, list) else endpoint.method_set
        
        # SQLi Logic
        if method_set.intersection({"GET", "POST"}) and parameter_name:
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="SQL Injection Test",
                test_type="sqli",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        # XSS Logic
        if "GET" in method_set and "html" in str(content_type).lower():
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="XSS Reflected Test",
                test_type="xss_reflected",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        # SSTI Logic
        if "POST" in method_set and "html" in str(content_type).lower():
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="SSTI Test",
                test_type="ssti",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        # Path Traversal
        if "GET" in method_set and "file" in parameter_name.lower():
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="Path Traversal Test",
                test_type="path_traversal",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        # Command Injection
        if "POST" in method_set and "cmd" in parameter_name.lower():
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="Command Injection Test",
                test_type="command",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        return applicable
