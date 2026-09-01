from enum import Enum
import logging

logger = logging.getLogger(__name__)

class LoginType(Enum):
    FORM = "form"
    SPA = "spa"
    OAUTH = "oauth"
    JWT_API = "jwt_api"
    UNKNOWN = "unknown"

class LoginDetector:
    """
    Heuristically determines the type of login mechanism.
    """
    
    def detect(self, page_content: str, url: str) -> LoginType:
        """
        Analyzes a URL or page source to determine the login type.
        """
        login_type = LoginType.UNKNOWN
        
        if "oauth" in url.lower() or "authorize" in url.lower():
            login_type = LoginType.OAUTH
        elif "type=\"password\"" in page_content.lower() and "<form" in page_content.lower():
            login_type = LoginType.FORM
        elif "/api/auth" in url.lower() or "/api/login" in url.lower():
            login_type = LoginType.JWT_API
        elif "React" in page_content or "Vue" in page_content or "ng-app" in page_content:
            if "login" in url.lower():
                login_type = LoginType.SPA
                
        logger.info(f"AUTH_FLOW_DISCOVERED type={login_type.value}")
        print(f"AUTH_FLOW_DISCOVERED type={login_type.value}")
        return login_type
