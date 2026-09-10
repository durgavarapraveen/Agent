import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_WEIGHTS = {
    "schema_found": 0.4,
    "schema_type_match": 0.5,
    "shape_match": 0.6,
    "auth_flow": 0.2,
    "content_type": 0.3,
    "content_type_html": 0.4,
    "websocket_upgrade": 0.8,
    "sse_content_type": 0.8,
    "grpc_content_type": 0.9,
    "protobuf_content_type": 0.8,
}


@dataclass
class InferenceResult:
    endpoint_id: str
    inferred_type: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


class SemanticInferenceEngine:
    def __init__(self, confidence_weights: Dict[str, float] = None):
        self.inferences: Dict[str, InferenceResult] = {}
        self._weights = confidence_weights or DEFAULT_CONFIDENCE_WEIGHTS

    def _w(self, key: str) -> float:
        return self._weights.get(key, 0.3)

    def infer_endpoint(self, endpoint_data: Dict[str, Any],
                       context: Dict[str, Any] = None) -> InferenceResult:
        evidence = []
        confidence = 0.0
        inferred_type = "unknown"
        context = context or {}

        # 1. Schema inference (OpenAPI, GraphQL)
        if "schema" in endpoint_data:
            evidence.append("Schema definition found")
            confidence += self._w("schema_found")
            schema_str = str(endpoint_data["schema"]).lower()
            if "graphql" in schema_str:
                inferred_type = "graphql"
                confidence += self._w("schema_type_match")
            elif "openapi" in schema_str or "swagger" in schema_str:
                inferred_type = "rest"
                confidence += self._w("schema_type_match")
            elif "wsdl" in schema_str or "soap" in schema_str:
                inferred_type = "soap"
                confidence += self._w("schema_type_match")

        # 2. Request shape inference
        if "request_shape" in endpoint_data:
            shape = endpoint_data["request_shape"]
            if isinstance(shape, dict):
                if "query" in shape and "variables" in shape:
                    evidence.append("Request shape matches GraphQL")
                    inferred_type = "graphql"
                    confidence += self._w("shape_match")
                elif any(k.startswith("soapenv:") for k in shape.keys()):
                    evidence.append("Request shape matches SOAP")
                    inferred_type = "soap"
                    confidence += self._w("shape_match")

        # 3. Auth flow context
        if context.get("auth_flow"):
            flow = context["auth_flow"].lower()
            if "oauth" in flow:
                evidence.append("Participates in OAuth flow")
                confidence += self._w("auth_flow")
            elif "saml" in flow:
                evidence.append("Participates in SAML flow")
                confidence += self._w("auth_flow")

        # 4. Protocol headers
        headers = endpoint_data.get("headers", {})
        if isinstance(headers, dict):
            upgrade = headers.get("Upgrade", headers.get("upgrade", "")).lower()
            if "websocket" in upgrade:
                evidence.append("WebSocket Upgrade header")
                inferred_type = "websocket"
                confidence += self._w("websocket_upgrade")

        # 5. Content-type fallback
        if inferred_type == "unknown" and "content_type" in endpoint_data:
            ct = endpoint_data["content_type"].lower()
            if "text/event-stream" in ct:
                inferred_type = "sse"
                confidence += self._w("sse_content_type")
                evidence.append("SSE content type observed")
            elif "grpc" in ct:
                inferred_type = "grpc_web"
                confidence += self._w("grpc_content_type")
                evidence.append("gRPC content type observed")
            elif "protobuf" in ct:
                inferred_type = "protobuf"
                confidence += self._w("protobuf_content_type")
                evidence.append("Protobuf content type observed")
            elif "json" in ct:
                inferred_type = "rest_json"
                confidence += self._w("content_type")
                evidence.append("JSON content type observed")
            elif "xml" in ct:
                inferred_type = "xml"
                confidence += self._w("content_type")
                evidence.append("XML content type observed")
            elif "text/html" in ct:
                inferred_type = "html_page"
                confidence += self._w("content_type_html")
                evidence.append("HTML content type observed")
            elif "multipart/form-data" in ct:
                inferred_type = "form_multipart"
                confidence += self._w("content_type")
                evidence.append("Multipart form content type observed")
            elif "application/x-www-form-urlencoded" in ct:
                inferred_type = "form_urlencoded"
                confidence += self._w("content_type")
                evidence.append("URL-encoded form content type observed")

        confidence = min(1.0, confidence)
        result = InferenceResult(
            endpoint_id=endpoint_data.get("endpoint_id", endpoint_data.get("url", "unknown")),
            inferred_type=inferred_type,
            confidence=confidence,
            evidence=evidence,
        )
        self.inferences[result.endpoint_id] = result
        return result

    def get_inference(self, endpoint_id: str) -> Optional[InferenceResult]:
        return self.inferences.get(endpoint_id)
