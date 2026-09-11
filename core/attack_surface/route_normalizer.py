from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class RouteNormalizer:
    @staticmethod
    def normalize_spa_route(url: str) -> Tuple[str, Optional[str]]:
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

    # ── Phase 8.5: pattern-based endpoint dedup ──────────────────────────────
    @staticmethod
    def pattern_key(url: str, method: str = "GET") -> str:
        """Stable pattern for an endpoint: /api/products/1 and /api/products/2
        collapse to 'GET /api/products/{id}'. Reuses workflow_crawler's
        id-collapsing path normalizer."""
        from core.discovery.workflow_crawler import normalize_path
        return f"{(method or 'GET').upper()} {normalize_path(url)}"

    @staticmethod
    def group_by_pattern(endpoints: List[Any]) -> Dict[str, List[Any]]:
        """Group endpoints by their normalized pattern so RESTful instances
        (/users/1, /users/2, …) share one entry."""
        groups: Dict[str, List[Any]] = {}
        for ep in endpoints:
            if isinstance(ep, dict):
                url, method = ep.get("url", ""), ep.get("method", "GET")
            else:
                url, method = getattr(ep, "url", str(ep)), getattr(ep, "method", "GET")
            groups.setdefault(RouteNormalizer.pattern_key(url, method), []).append(ep)
        return groups

    @staticmethod
    def representatives(endpoints: List[Any], per_pattern: int = 1) -> List[Any]:
        """Pick up to `per_pattern` representatives from each pattern group — the
        endpoints actually worth testing; findings apply to the whole group."""
        out: List[Any] = []
        for _pat, eps in RouteNormalizer.group_by_pattern(endpoints).items():
            out.extend(eps[:max(1, per_pattern)])
        return out

    @staticmethod
    def coverage_map(endpoints: List[Any], per_pattern: int = 1) -> Dict[str, Dict[str, Any]]:
        """Report, per pattern: representatives to test and the count covered by
        applying their result to the rest."""
        result: Dict[str, Dict[str, Any]] = {}
        for pat, eps in RouteNormalizer.group_by_pattern(endpoints).items():
            reps = eps[:max(1, per_pattern)]
            result[pat] = {"total": len(eps), "tested": len(reps),
                           "covered_by_pattern": len(eps) - len(reps)}
        return result
