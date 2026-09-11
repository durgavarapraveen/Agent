
import json
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Common paths where API specs are exposed
OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui/swagger.json",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
]

GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql",
    "/v1/graphql", "/gql", "/query",
]

GRAPHQL_INTROSPECTION_QUERY = '{"query":"{ __schema { types { name kind fields { name args { name type { name kind ofType { name kind } } } } } } }"}'


class APISchemaImporter:

    def __init__(self, target: str, timeout: int = 15, artifacts=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.endpoints: List[Dict] = []
        self.schema_source: Optional[str] = None
        # P1.3: an ArtifactRegistry of already-discovered schemas; consumed
        # before re-probing the hardcoded path list.
        self.artifacts = artifacts

    def _registered_urls(self, *types) -> List[str]:
        if self.artifacts is None:
            return []
        try:
            return list(self.artifacts.urls_of(*types))
        except Exception:
            return []

    def _fetch(self, url: str) -> Tuple[int, str]:
        import shlex
        from agents.kali_executor import KaliDockerExecutor
        safe_url = shlex.quote(url)
        cmd = (
            f'curl -s -o /tmp/schema_probe.txt -w "%{{http_code}}" '
            f'-L -k --max-time {int(self.timeout)} '
            f'-H "Accept: application/json, application/yaml, text/yaml" '
            f'{safe_url}'
        )
        result = KaliDockerExecutor.run(cmd, timeout=self.timeout + 10)
        if result.get("status") != "success":
            return 0, ""
        # curl `-w "%{http_code}"` prints the numeric status as the LAST
        # 3 chars of stdout. If curl fails hard the buffer may be shorter or
        # non-numeric; use a regex to extract the trailing 3-digit token and
        # log at DEBUG so misparses are diagnosable instead of appearing as 0.
        import re as _re_scode
        status = 0
        stdout = (result.get("stdout") or "").strip()
        m = _re_scode.search(r"(\d{3})\s*$", stdout)
        if m:
            try:
                status = int(m.group(1))
            except ValueError:
                logger.debug("Failed to parse HTTP status from tail: %r", stdout[-16:])
        else:
            logger.debug("No trailing HTTP status in curl output: %r", stdout[-32:])
        body_r = KaliDockerExecutor.run("cat /tmp/schema_probe.txt", timeout=5)
        body = body_r.get("stdout", "") if body_r.get("status") == "success" else ""
        return status, body

    def _fetch_post(self, url: str, data: str, content_type: str = "application/json") -> Tuple[int, str]:
        import shlex
        from agents.kali_executor import KaliDockerExecutor
        safe_url = shlex.quote(url)
        safe_data = shlex.quote(data)
        safe_header = shlex.quote(f"Content-Type: {content_type}")
        cmd = (
            f'curl -s -o /tmp/schema_probe.txt -w "%{{http_code}}" '
            f'-L -k --max-time {int(self.timeout)} -X POST '
            f'-H {safe_header} '
            f'-d {safe_data} {safe_url}'
        )
        result = KaliDockerExecutor.run(cmd, timeout=self.timeout + 10)
        if result.get("status") != "success":
            return 0, ""
        # curl `-w "%{http_code}"` prints the numeric status as the LAST
        # 3 chars of stdout. If curl fails hard the buffer may be shorter or
        # non-numeric; use a regex to extract the trailing 3-digit token and
        # log at DEBUG so misparses are diagnosable instead of appearing as 0.
        import re as _re_scode
        status = 0
        stdout = (result.get("stdout") or "").strip()
        m = _re_scode.search(r"(\d{3})\s*$", stdout)
        if m:
            try:
                status = int(m.group(1))
            except ValueError:
                logger.debug("Failed to parse HTTP status from tail: %r", stdout[-16:])
        else:
            logger.debug("No trailing HTTP status in curl output: %r", stdout[-32:])
        body_r = KaliDockerExecutor.run("cat /tmp/schema_probe.txt", timeout=5)
        body = body_r.get("stdout", "") if body_r.get("status") == "success" else ""
        return status, body

    def discover_openapi(self) -> Optional[Dict]:
        candidates: List[str] = []
        for u in self._registered_urls("OPENAPI", "SWAGGER"):
            if u:
                candidates.append(u)
        candidates.extend(f"{self.target}{path}" for path in OPENAPI_PATHS)
        seen = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            status, body = self._fetch(url)
            if status != 200 or not body.strip():
                continue
            try:
                spec = json.loads(body)
                if self._is_openapi_spec(spec):
                    logger.info(f"[APIImporter] OpenAPI spec found at {url}")
                    self.schema_source = url
                    return spec
            except json.JSONDecodeError:
                # Try YAML
                try:
                    import yaml
                    spec = yaml.safe_load(body)
                    if isinstance(spec, dict) and self._is_openapi_spec(spec):
                        logger.info(f"[APIImporter] OpenAPI YAML spec found at {url}")
                        self.schema_source = url
                        return spec
                except yaml.YAMLError as ye:
                    logger.debug("[APIImporter] YAML parse failed for %s: %s", url, ye)
                except ImportError:
                    logger.debug("[APIImporter] pyyaml not installed; skipping YAML fallback")
                except Exception as e:
                    logger.debug("[APIImporter] Unexpected YAML fallback error for %s: %s", url, e)
        return None

    def _is_openapi_spec(self, spec: dict) -> bool:
        if not isinstance(spec, dict):
            return False
        return bool(
            spec.get("openapi") or
            spec.get("swagger") or
            (spec.get("paths") and spec.get("info"))
        )

    def discover_graphql(self) -> Optional[Dict]:
        for path in GRAPHQL_PATHS:
            url = f"{self.target}{path}"
            status, body = self._fetch_post(url, GRAPHQL_INTROSPECTION_QUERY)
            if status != 200 or not body.strip():
                # Try GET with query param
                get_url = f"{url}?query=%7B%20__schema%20%7B%20types%20%7B%20name%20kind%20%7D%20%7D%20%7D"
                status, body = self._fetch(get_url)
                if status != 200 or not body.strip():
                    continue
            try:
                result = json.loads(body)
                if "data" in result and "__schema" in result.get("data", {}):
                    logger.info(f"[APIImporter] GraphQL introspection found at {url}")
                    self.schema_source = url
                    return result
            except json.JSONDecodeError:
                pass
        return None

    def parse_openapi(self, spec: Dict) -> List[Dict]:

        base_url = self.target
        # Extract server base from spec
        if "servers" in spec:
            servers = spec["servers"]
            if servers and isinstance(servers, list):
                server_url = servers[0].get("url", "")
                if server_url.startswith("http"):
                    base_url = server_url.rstrip("/")
                elif server_url.startswith("/"):
                    base_url = f"{self.target}{server_url.rstrip('/')}"
        elif "basePath" in spec:
            base_url = f"{self.target}{spec['basePath'].rstrip('/')}"

        paths = spec.get("paths", {})
        endpoints = []

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, operation in methods.items():
                method_upper = method.upper()
                if method_upper not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    continue
                if not isinstance(operation, dict):
                    continue

                full_url = f"{base_url}{path}"
                params = []

                # Parse parameters
                all_params = (operation.get("parameters") or []) + (methods.get("parameters") or [])
                for p in all_params:
                    if not isinstance(p, dict):
                        continue
                    # Resolve $ref
                    if "$ref" in p:
                        p = self._resolve_ref(spec, p["$ref"])
                        if not p:
                            continue

                    param_in = p.get("in", "query")
                    type_map = {
                        "query": "QUERY", "path": "PATH", "header": "HEADER",
                        "cookie": "COOKIE", "body": "BODY",
                    }
                    param_type_str = type_map.get(param_in, "UNKNOWN")

                    schema = p.get("schema", {})
                    data_type = schema.get("type", p.get("type", "string"))

                    params.append({
                        "name": p.get("name", ""),
                        "parameter_type": param_type_str,
                        "inferred_data_type": data_type,
                        "is_required": p.get("required", False),
                    })

                # Parse requestBody (OpenAPI 3.x)
                req_body = operation.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for media_type, media_spec in content.items():
                        if not isinstance(media_spec, dict):
                            continue
                        schema = media_spec.get("schema", {})
                        if "$ref" in schema:
                            schema = self._resolve_ref(spec, schema["$ref"]) or {}
                        body_params = self._extract_schema_params(spec, schema)
                        for bp in body_params:
                            bp["parameter_type"] = "BODY"
                        params.extend(body_params)

                # Determine auth requirement
                security = operation.get("security", spec.get("security", []))
                auth_required = bool(security)

                endpoint = {
                    "url": full_url,
                    "path": path,
                    "method": method_upper,
                    "parameters": params,
                    "auth_required": auth_required,
                    "source": "openapi",
                    "schema_url": self.schema_source,
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary", ""),
                    "tags": operation.get("tags", []),
                }
                endpoints.append(endpoint)

        self.endpoints = endpoints
        logger.info(f"[APIImporter] Parsed {len(endpoints)} endpoints from OpenAPI spec")
        return endpoints

    def parse_graphql(self, introspection: Dict) -> List[Dict]:
        schema = introspection.get("data", {}).get("__schema", {})
        types = schema.get("types", [])

        mutations = []
        queries = []

        for t in types:
            if not isinstance(t, dict):
                continue
            name = t.get("name", "")
            kind = t.get("kind", "")
            fields = t.get("fields") or []

            if name in ("Query", "Mutation", "Subscription"):
                for field in fields:
                    if not isinstance(field, dict):
                        continue
                    field_name = field.get("name", "")
                    args = field.get("args", [])
                    params = []
                    for arg in args:
                        if isinstance(arg, dict):
                            arg_type = arg.get("type", {})
                            type_name = self._graphql_type_name(arg_type)
                            params.append({
                                "name": arg.get("name", ""),
                                "parameter_type": "BODY",
                                "inferred_data_type": type_name,
                                "is_required": arg_type.get("kind") == "NON_NULL",
                            })

                    entry = {
                        "url": self.schema_source or f"{self.target}/graphql",
                        "path": f"/graphql#{name}.{field_name}",
                        "method": "POST",
                        "parameters": params,
                        "auth_required": False,
                        "source": "graphql_introspection",
                        "operation_id": f"{name}.{field_name}",
                        "graphql_type": name,
                    }
                    if name == "Query":
                        queries.append(entry)
                    else:
                        mutations.append(entry)

        endpoints = queries + mutations
        self.endpoints = endpoints
        logger.info(f"[APIImporter] Parsed {len(queries)} queries, {len(mutations)} mutations from GraphQL")
        return endpoints

    def _resolve_ref(self, spec: Dict, ref: str) -> Optional[Dict]:
        if not ref.startswith("#/"):
            return None
        parts = ref[2:].split("/")
        node = spec
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node if isinstance(node, dict) else None

    def _extract_schema_params(self, spec: Dict, schema: Dict, prefix: str = "") -> List[Dict]:
        params = []
        if not isinstance(schema, dict):
            return params

        if "$ref" in schema:
            schema = self._resolve_ref(spec, schema["$ref"]) or {}

        schema_type = schema.get("type", "object")
        required_fields = set(schema.get("required", []))

        if schema_type == "object" and "properties" in schema:
            for prop_name, prop_schema in schema["properties"].items():
                if "$ref" in prop_schema:
                    prop_schema = self._resolve_ref(spec, prop_schema["$ref"]) or {}
                full_name = f"{prefix}.{prop_name}" if prefix else prop_name
                params.append({
                    "name": full_name,
                    "parameter_type": "BODY",
                    "inferred_data_type": prop_schema.get("type", "string"),
                    "is_required": prop_name in required_fields,
                })
        elif schema_type == "array" and "items" in schema:
            items = schema["items"]
            if "$ref" in items:
                items = self._resolve_ref(spec, items["$ref"]) or {}
            sub_params = self._extract_schema_params(spec, items, prefix=f"{prefix}[]" if prefix else "[]")
            params.extend(sub_params)

        return params

    def _graphql_type_name(self, type_obj: Dict) -> str:
        if not isinstance(type_obj, dict):
            return "String"
        name = type_obj.get("name")
        if name:
            return name
        of_type = type_obj.get("ofType")
        if of_type:
            return self._graphql_type_name(of_type)
        return type_obj.get("kind", "String")

    def to_domain_endpoints(self) -> list:
        from core.domain.endpoint import Endpoint
        from core.domain.parameter import Parameter, ParameterType

        type_map = {
            "QUERY": ParameterType.QUERY,
            "PATH": ParameterType.PATH,
            "BODY": ParameterType.BODY,
            "HEADER": ParameterType.HEADER,
            "COOKIE": ParameterType.COOKIE,
            "UNKNOWN": ParameterType.UNKNOWN,
        }

        domain_eps = []
        for i, ep in enumerate(self.endpoints):
            params = []
            for p in ep.get("parameters", []):
                pt = type_map.get(p.get("parameter_type", "UNKNOWN"), ParameterType.UNKNOWN)
                params.append(Parameter(
                    name=p["name"],
                    parameter_type=pt,
                    inferred_data_type=p.get("inferred_data_type", "string"),
                    is_required=p.get("is_required", False),
                ))

            domain_ep = Endpoint(
                endpoint_id=f"api-{i+1}",
                url=ep.get("url", ""),
                path=ep.get("path", ""),
                method_set=[ep.get("method", "GET")],
                parameters=params,
                auth_required=ep.get("auth_required", False),
            )
            domain_eps.append(domain_ep)
        return domain_eps

    def import_all(self) -> List[Dict]:
        spec = self.discover_openapi()
        if spec:
            return self.parse_openapi(spec)

        gql = self.discover_graphql()
        if gql:
            return self.parse_graphql(gql)

        logger.info("[APIImporter] No API schema discovered")
        return []
