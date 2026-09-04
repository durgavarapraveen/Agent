import logging
from core.identity.session_manager import SessionArtifact

logger = logging.getLogger(__name__)

class SessionValidator:
    """
    Validates if an active session is still authenticated.
    """
    
    def __init__(self, session_manager, validation_endpoint: str = "/api/me"):
        self.session_manager = session_manager
        self.validation_endpoint = validation_endpoint
        
    def is_valid(self, session: SessionArtifact, base_url: str = "") -> bool:
        """
        Validate a session for real: send a request to `validation_endpoint`
        using the session's cookies/headers and treat a non-401/403 response as
        still authenticated. Falls back to the session's own validity flag only
        when no base_url is available to probe.
        """
        if not session or not session.is_valid:
            self.session_manager.auth_health_metrics["session_expirations"] += 1
            logger.info(f"SESSION_EXPIRED identity={session.identity_id if session else 'unknown'}")
            return False

        if base_url:
            try:
                import httpx
                url = base_url.rstrip("/") + self.validation_endpoint
                headers = dict(session.headers or {})
                if session.cookies:
                    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
                resp = httpx.get(url, headers=headers, timeout=10, follow_redirects=True)
                alive = resp.status_code not in (401, 403)
                if not alive:
                    self.session_manager.auth_health_metrics["session_expirations"] += 1
                    logger.info(f"SESSION_EXPIRED identity={session.identity_id} (HTTP {resp.status_code})")
                    return False
            except Exception as e:
                logger.debug(f"[SessionValidator] probe failed, using cached validity: {e}")

        self.session_manager.auth_health_metrics["session_validations"] += 1
        logger.info(f"SESSION_VALIDATED identity={session.identity_id}")
        return True
