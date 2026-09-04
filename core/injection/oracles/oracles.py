from typing import Any
from core.domain.request import ResponseData
from core.domain.endpoint import Endpoint

class BaseOracle:
    def validate(self, response: ResponseData, payload: str, baseline: ResponseData, endpoint: Endpoint) -> bool:
        raise NotImplementedError()

class ReflectionOracle(BaseOracle):
    def validate(self, response: ResponseData, payload: str, baseline: ResponseData, endpoint: Endpoint) -> bool:
        body = response.body.decode('utf-8', errors='ignore') if isinstance(response.body, bytes) else str(response.body)
        return payload in body

class DifferentialResponseOracle(BaseOracle):
    def validate(self, response: ResponseData, payload: str, baseline: ResponseData, endpoint: Endpoint) -> bool:
        return response.status_code != baseline.status_code or len(response.body) != len(baseline.body)
