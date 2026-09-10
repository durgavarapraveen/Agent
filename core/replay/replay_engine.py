import logging
import json
import uuid
import copy
from types import SimpleNamespace
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

from core.domain.request import CapturedRequest, ResponseData
from core.domain.identity import Identity
from core.replay.session_manager import SessionManager
from core.replay.http_proxy import HttpProxy

logger = logging.getLogger(__name__)

class ReplayEngine:
    def __init__(self, session_manager: SessionManager, proxy: HttpProxy):
        self.session_manager = session_manager
        self.proxy = proxy
        
    def replay_request(self, request: CapturedRequest, identity: Identity) -> CapturedRequest:
        req_copy = copy.deepcopy(request)
        
        # 1. Get or create session for the identity
        session = self.session_manager.get_session(identity.identity_id)
        if not session or not self.session_manager.validate_session(session):
            session = self.session_manager.create_session(identity)
            
        # 2. Strip old auth and inject new session
        # Strip Authorization headers
        headers_to_remove = [k for k in req_copy.full_headers if k.lower() == 'authorization']
        for k in headers_to_remove:
            del req_copy.full_headers[k]
            
        # Inject new headers
        for k, v in session.tokens.items():
            req_copy.full_headers[k] = v
            
        # Inject new cookies
        for k, v in session.cookies.items():
            req_copy.cookies[k] = v
            
        # 3. Fire request
        req_copy.identity_id = identity.identity_id
        req_copy.session_id = session.session_id
        
        response = self.proxy.forward(req_copy)
        req_copy.response = response
        
        return req_copy

    def replay(self, request_node: Any, identity_id: Optional[str] = None) -> Optional[ResponseData]:
        req = request_node.get("request") if isinstance(request_node, dict) else request_node
        if req is None:
            return None

        # Anonymous replay: strip any inherited auth and send.
        if identity_id is None:
            rc = copy.deepcopy(req)
            for k in [h for h in list(rc.full_headers) if h.lower() == "authorization"]:
                del rc.full_headers[k]
            try:
                rc.cookies = {}
            except Exception:
                pass
            try:
                rc.identity_id = ""   # anonymous (identity_id is a required string field)
            except Exception:
                pass
            resp = self.proxy.forward(rc)
            rc.response = resp
            return resp

        # Authenticated replay as a specific identity (uses a pre-loaded real session).
        shim = SimpleNamespace(identity_id=identity_id)
        try:
            replayed = self.replay_request(req, shim)
            return getattr(replayed, "response", None)
        except Exception as e:
            logger.debug(f"[ReplayEngine] replay as '{identity_id}' failed: {e}")
            return None

    def replay_with_modifications(self, request: CapturedRequest, identity: Identity, modifications: Dict[str, Any]) -> CapturedRequest:
        req_copy = copy.deepcopy(request)
        
        # Modify query params
        if "query" in modifications:
            parsed_url = urlparse(req_copy.url)
            query_dict = dict(parse_qsl(parsed_url.query))
            query_dict.update(modifications["query"])
            
            new_query = urlencode(query_dict)
            new_url_parts = list(parsed_url)
            new_url_parts[4] = new_query
            req_copy.url = urlunparse(new_url_parts)
            
        # Modify body
        if "body" in modifications and req_copy.body:
            try:
                body_str = req_copy.body.decode('utf-8')
                data = json.loads(body_str)
                if isinstance(data, dict):
                    data.update(modifications["body"])
                    req_copy.body = json.dumps(data).encode('utf-8')
            except Exception as e:
                logger.error(f"Failed to apply body modifications: {e}")
                
        return self.replay_request(req_copy, identity)

    def validate_response_schema(self, response: ResponseData, expected_status: int) -> bool:
        return response.status_code == expected_status

    def get_response_diff(self, response1: ResponseData, response2: ResponseData) -> Dict[str, Any]:
        return {
            "status_code_changed": response1.status_code != response2.status_code,
            "status_1": response1.status_code,
            "status_2": response2.status_code,
            "length_difference": len(response1.body) - len(response2.body)
        }
