import re
from urllib.parse import urlparse

class RouteNormalizer:
    """
    Normalizes paths to prevent graph bloat by collapsing dynamic segments into standard patterns.
    Also handles SPA fragment normalization.
    """
    
    def __init__(self):
        self.patterns = [
            (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), '{uuid}'),
            (re.compile(r'\b[0-9a-fA-F]{10,}\b'), '{hash}'),
            (re.compile(r'/(?:\d+)(/|$)'), r'/{id}\1'),
        ]

    def normalize(self, path: str) -> str:
        """
        Normalizes dynamic REST API paths and SPA fragments.
        e.g., https://host/#/route -> /#/route
        """
        # If it's a full URL, extract path + fragment
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            # Preserve the client route (SPA hash) but ensure it's not mixed with standard HTTP paths
            normalized = parsed.path
            if parsed.fragment:
                normalized += "#" + parsed.fragment
        else:
            normalized = path
            
        # Collapse dynamic parts
        for pattern, replacement in self.patterns:
            normalized = pattern.sub(replacement, normalized)
            
        normalized = re.sub(r'//+', '/', normalized)
        
        return normalized
