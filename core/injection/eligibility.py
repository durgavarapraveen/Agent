from typing import List, Optional
from core.domain.endpoint import Endpoint
from core.domain.identity import Identity
from core.injection.models import InjectionTest
from core.common import target_shape as ts
from core.orchestration import scan_mode
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
            
        # Path Traversal — semantic file-param classification (name/value shape),
        # not a bare "file" substring gate.
        if "GET" in method_set and ts.is_file_param(parameter_name):
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="Path Traversal Test",
                test_type="path_traversal",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        # Command Injection — cmd-name is only a weak hint (cmd-i can live in any
        # param). Fire on the hint, or on any param outside FAST mode.
        if "POST" in method_set and (
            ts.is_cmd_param(parameter_name) or scan_mode.mode() != scan_mode.FAST
        ):
            applicable.append(InjectionTest(
                test_id=str(uuid.uuid4()),
                name="Command Injection Test",
                test_type="command",
                endpoint_id=endpoint.endpoint_id,
                parameter_name=parameter_name
            ))
            
        return applicable
