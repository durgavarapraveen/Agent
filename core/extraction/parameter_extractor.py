from typing import List, Any
from urllib.parse import parse_qs, urlparse
from core.domain.parameter import Parameter, ParameterType
from core.domain.request import CapturedRequest
import json

class ParameterExtractor:
    @staticmethod
    def extract_from_request(request: CapturedRequest) -> List[Parameter]:
        params = []
        
        # 1. Query Parameters
        parsed_url = urlparse(request.url)
        if parsed_url.query:
            query_dict = parse_qs(parsed_url.query)
            for key, values in query_dict.items():
                inferred = ParameterExtractor._infer_type(values[0])
                params.append(Parameter(
                    name=key,
                    parameter_type=ParameterType.QUERY,
                    inferred_data_type=inferred,
                    is_required=False # Can't definitively know yet
                ))
                
        # 2. Header Parameters
        # Usually we only care about custom or important headers (X-*, Authorization, etc)
        # We will extract all for comprehensiveness and let downstream logic filter.
        for key, val in request.full_headers.items():
            params.append(Parameter(
                name=key,
                parameter_type=ParameterType.HEADER,
                inferred_data_type="string",
                is_required=False
            ))
            
        # 3. Cookie Parameters
        for key, val in request.cookies.items():
            params.append(Parameter(
                name=key,
                parameter_type=ParameterType.COOKIE,
                inferred_data_type="string",
                is_required=False
            ))
            
        # 4. Body Parameters (JSON)
        # Heuristic based on content type or ability to parse json
        if request.body:
            try:
                body_str = request.body.decode('utf-8')
                data = json.loads(body_str)
                if isinstance(data, dict):
                    for key, val in data.items():
                        inferred = ParameterExtractor._infer_type(val)
                        params.append(Parameter(
                            name=key,
                            parameter_type=ParameterType.BODY,
                            inferred_data_type=inferred,
                            is_required=False
                        ))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
                
        return params
        
    @staticmethod
    def _infer_type(value: Any) -> str:
        if isinstance(value, bool):
            return "bool"
        elif isinstance(value, int):
            return "int"
        elif isinstance(value, float):
            return "float"
        elif isinstance(value, list):
            return "array"
        elif isinstance(value, dict):
            return "object"
        elif isinstance(value, str):
            # Check if it looks like an int
            if value.lstrip('-').isdigit():
                return "int"
            if value.lower() in ['true', 'false']:
                return "bool"
            return "string"
        return "string"
