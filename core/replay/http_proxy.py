import requests
import logging
from typing import Dict, Any
from core.domain.request import CapturedRequest, ResponseData

logger = logging.getLogger(__name__)

class HttpProxy:
    def __init__(self, verify_ssl: bool = False):
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        # Suppress insecure request warnings if verify_ssl is False
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
    def forward(self, request: CapturedRequest) -> ResponseData:
        logger.info(f"Forwarding {request.method} {request.url}")
        
        # We need to construct the kwargs for the requests call
        req_kwargs: Dict[str, Any] = {
            "method": request.method,
            "url": request.url,
            "headers": request.full_headers.copy(),
            "cookies": request.cookies.copy(),
            "verify": self.verify_ssl,
            "allow_redirects": False # We want to capture exactly what happens
        }
        
        if request.body:
            req_kwargs["data"] = request.body
            
        try:
            resp = self.session.request(**req_kwargs)
            
            # Map back to ResponseData
            return ResponseData(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
                body_hash="" # Can hash later if needed
            )
        except Exception as e:
            logger.error(f"Failed to forward request to {request.url}: {e}")
            # Returning a 0 status code to represent a connection error natively
            return ResponseData(
                status_code=0,
                headers={},
                body=str(e).encode('utf-8')
            )
