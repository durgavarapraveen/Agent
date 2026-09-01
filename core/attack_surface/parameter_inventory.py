from typing import List, Dict
from core.domain.parameter import Parameter
import logging

logger = logging.getLogger(__name__)

class ParameterInventory:
    def __init__(self):
        # Maps endpoint_id -> list of Parameters
        self.by_endpoint: Dict[str, List[Parameter]] = {}
        # Maps parameter type -> list of Parameters globally
        self.by_type: Dict[str, List[Parameter]] = {}
        
    def add_parameter(self, endpoint_id: str, param: Parameter):
        if endpoint_id not in self.by_endpoint:
            self.by_endpoint[endpoint_id] = []
            
        # Avoid exact duplicates per endpoint
        existing_names = {p.name for p in self.by_endpoint[endpoint_id]}
        if param.name not in existing_names:
            self.by_endpoint[endpoint_id].append(param)
            
            p_type = param.parameter_type.value
            if p_type not in self.by_type:
                self.by_type[p_type] = []
            self.by_type[p_type].append(param)
            
            logger.info(f"PARAMETER_MODEL_CREATED endpoint_id={endpoint_id} parameter={param.name} param_type={p_type}")
            print(f"PARAMETER_MODEL_CREATED endpoint_id={endpoint_id} parameter={param.name} param_type={p_type}")
            
    def get_parameters_for_endpoint(self, endpoint_id: str) -> List[Parameter]:
        return self.by_endpoint.get(endpoint_id, [])
        
    def get_parameters_by_type(self) -> Dict[str, List[Parameter]]:
        return self.by_type
