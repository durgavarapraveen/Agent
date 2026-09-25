from enum import Enum
import logging
from core.common import target_shape as ts

logger = logging.getLogger(__name__)

class LoginType(Enum):
    FORM = "form"
    SPA = "spa"
    OAUTH = "oauth"
    JWT_API = "jwt_api"
    UNKNOWN = "unknown"

class LoginDetector:
    
    def detect(self, page_content: str, url: str) -> LoginType:
        login_type = LoginType.UNKNOWN
        
        has_password_field = "type=\"password\"" in page_content.lower()

        if "oauth" in url.lower() or "authorize" in url.lower():
            login_type = LoginType.OAUTH
        elif has_password_field and "<form" in page_content.lower():
            login_type = LoginType.FORM
        elif ts.is_login_endpoint(url):
            login_type = LoginType.JWT_API
        elif "React" in page_content or "Vue" in page_content or "ng-app" in page_content:
            # SPA login: URL hint, a login-shaped endpoint, or an observed
            # password field in the rendered form — not just "login" in url.
            if "login" in url.lower() or ts.is_login_endpoint(url) or has_password_field:
                login_type = LoginType.SPA
                
        logger.info(f"AUTH_FLOW_DISCOVERED type={login_type.value}")
        print(f"AUTH_FLOW_DISCOVERED type={login_type.value}")
        return login_type
