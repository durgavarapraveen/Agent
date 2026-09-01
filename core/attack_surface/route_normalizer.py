from typing import Tuple, Optional
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class RouteNormalizer:
    @staticmethod
    def normalize_spa_route(url: str) -> Tuple[str, Optional[str]]:
        """
        Normalizes a URL into its server-side HTTP path and its client-side SPA route.
        """
        parsed = urlparse(url)
        http_path = parsed.path if parsed.path else "/"
        
        spa_route = None
        if parsed.fragment:
            # Check if it looks like a route (e.g., #/users/42 or #!/users/42)
            fragment = parsed.fragment
            if fragment.startswith("/") or fragment.startswith("!/"):
                spa_route = fragment
                if spa_route.startswith("!/"):
                    spa_route = spa_route[1:]
                logger.info(f"SPA_ROUTE_NORMALIZED original={url} http_path={http_path} spa_route={spa_route}")
                print(f"SPA_ROUTE_NORMALIZED original={url} http_path={http_path} spa_route={spa_route}")
                
        return http_path, spa_route
