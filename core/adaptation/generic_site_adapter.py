import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class AuthModel(str, Enum):
    COOKIE = "cookie"
    JWT = "jwt"
    API_KEY = "api_key"
    OAUTH = "oauth"
    MFA = "mfa"
    BASIC = "basic"
    NONE = "none"
    UNKNOWN = "unknown"


class APIStructure(str, Enum):
    REST = "rest"
    GRAPHQL = "graphql"
    SOAP = "soap"
    GRPC = "grpc"
    UNKNOWN = "unknown"


TECH_TEST_MAP = {
    "php": ["input_validation.sqli", "input_validation.cmdi", "file_upload.arbitrary_write", "path_traversal.lfi"],
    "django": ["input_validation.ssti", "csrf.basic", "authentication.basic"],
    "flask": ["input_validation.ssti", "input_validation.sqli"],
    "express": ["input_validation.nosqli", "xss.reflected", "ssrf.basic"],
    "nodejs": ["input_validation.nosqli", "xss.reflected", "ssrf.basic"],
    "java": ["input_validation.sqli", "xxe.basic", "input_validation.ssti"],
    "dotnet": ["input_validation.sqli", "xxe.basic", "path_traversal.lfi"],
    "wordpress": ["authentication.brute_force", "input_validation.sqli", "file_upload.arbitrary_write"],
    "react": ["xss.dom", "xss.reflected"],
    "angular": ["xss.dom", "xss.reflected"],
    "vue": ["xss.dom", "xss.reflected"],
    "graphql": ["graphql.introspection", "graphql.injection", "authorization.idor"],
    "apache": ["misconfiguration.server", "path_traversal.lfi"],
    "nginx": ["misconfiguration.server"],
}

AUTH_TEST_MAP = {
    AuthModel.COOKIE: ["session.hijacking", "csrf.basic", "authentication.basic"],
    AuthModel.JWT: ["jwt.manipulation", "jwt.unsigned", "jwt.forgery"],
    AuthModel.API_KEY: ["authentication.api_key_leak", "authorization.idor"],
    AuthModel.OAUTH: ["authentication.oauth_redirect", "authorization.idor"],
    AuthModel.MFA: ["authentication.mfa_bypass"],
    AuthModel.BASIC: ["authentication.brute_force", "authentication.default_creds"],
    AuthModel.NONE: ["authorization.idor", "information_disclosure.error_messages"],
}

API_TEST_MAP = {
    APIStructure.REST: ["authorization.idor", "input_validation.sqli", "input_validation.general"],
    APIStructure.GRAPHQL: ["graphql.introspection", "graphql.injection", "authorization.idor"],
    APIStructure.SOAP: ["xxe.basic", "input_validation.sqli"],
}

UNIVERSAL_TESTS = [
    "xss.reflected",
    "information_disclosure.error_messages",
    "misconfiguration.server",
    "cryptography.weak_crypto",
    "input_validation.general",
]


@dataclass
class SiteProfile:
    target_url: str = ""
    technology_stack: List[str] = field(default_factory=list)
    auth_model: AuthModel = AuthModel.UNKNOWN
    api_structure: APIStructure = APIStructure.UNKNOWN
    applicable_tests: List[str] = field(default_factory=list)
    server: str = ""
    framework: str = ""
    frontend: str = ""
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "technology_stack": self.technology_stack,
            "auth_model": self.auth_model.value,
            "api_structure": self.api_structure.value,
            "applicable_tests": self.applicable_tests,
            "server": self.server,
            "framework": self.framework,
            "frontend": self.frontend,
        }


class GenericSiteAdapter:
    def __init__(self, target_url: str, headers: Optional[Dict[str, str]] = None,
                 body_content: str = ""):
        self.target_url = target_url.rstrip("/")
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body_content = body_content

    def profile(self) -> SiteProfile:
        sp = SiteProfile(target_url=self.target_url)

        sp.technology_stack = self._detect_tech()
        sp.server = self._detect_server()
        sp.framework = self._detect_framework()
        sp.frontend = self._detect_frontend()
        sp.auth_model = self._detect_auth_model()
        sp.api_structure = self._detect_api_structure()
        sp.raw_headers = dict(self.headers)
        sp.applicable_tests = self._compute_applicable_tests(sp)

        logger.info(f"SITE_PROFILE target={self.target_url} tech={sp.technology_stack} "
                     f"auth={sp.auth_model.value} api={sp.api_structure.value} "
                     f"tests={len(sp.applicable_tests)}")
        return sp

    def _detect_tech(self) -> List[str]:
        techs = []
        header_str = " ".join(f"{k}: {v}" for k, v in self.headers.items())
        combined = (header_str + " " + self.body_content).lower()

        signatures = {
            "php": ["x-powered-by: php", ".php", "php/"],
            "django": ["csrftoken", "django", "x-frame-options"],
            "flask": ["werkzeug", "flask"],
            "express": ["x-powered-by: express", "express"],
            "nodejs": ["node", "x-powered-by: express"],
            "java": ["tomcat", "jboss", "weblogic", "jetty", ".jsp"],
            "dotnet": ["asp.net", "x-aspnet", ".aspx"],
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "react": ["react", "_reactroot", "react-dom"],
            "angular": ["ng-version", "ng-app", "angular"],
            "vue": ["__vue__", "vue-router", "v-app"],
            "graphql": ["graphql", "graphiql", "__schema"],
            "apache": ["apache"],
            "nginx": ["nginx"],
            "ruby": ["phusion passenger", "x-powered-by: phusion"],
        }

        for tech, sigs in signatures.items():
            if any(sig in combined for sig in sigs):
                techs.append(tech)
        return techs

    def _detect_server(self) -> str:
        server = self.headers.get("server", "")
        x_powered = self.headers.get("x-powered-by", "")
        return server or x_powered or "unknown"

    def _detect_framework(self) -> str:
        techs = self._detect_tech()
        frameworks = ["django", "flask", "express", "dotnet", "wordpress"]
        for f in frameworks:
            if f in techs:
                return f
        return ""

    def _detect_frontend(self) -> str:
        techs = self._detect_tech()
        for f in ("react", "angular", "vue"):
            if f in techs:
                return f
        return ""

    def _detect_auth_model(self) -> AuthModel:
        header_str = " ".join(f"{k}: {v}" for k, v in self.headers.items()).lower()
        combined = header_str + " " + self.body_content.lower()

        if "bearer" in combined or "jwt" in combined or "eyj" in combined:
            return AuthModel.JWT
        if "set-cookie" in combined or "cookie" in self.headers:
            return AuthModel.COOKIE
        if "x-api-key" in combined or "apikey" in combined:
            return AuthModel.API_KEY
        if "oauth" in combined or "authorization_code" in combined:
            return AuthModel.OAUTH
        if "www-authenticate" in combined and "basic" in combined:
            return AuthModel.BASIC
        return AuthModel.UNKNOWN

    def _detect_api_structure(self) -> APIStructure:
        combined = (self.target_url + " " + self.body_content).lower()
        if "graphql" in combined or "graphiql" in combined:
            return APIStructure.GRAPHQL
        if "wsdl" in combined or "soap" in combined or "xmlns" in combined:
            return APIStructure.SOAP
        if "/api/" in combined or "/v1/" in combined or "/v2/" in combined:
            return APIStructure.REST
        return APIStructure.UNKNOWN

    def _compute_applicable_tests(self, sp: SiteProfile) -> List[str]:
        tests = set(UNIVERSAL_TESTS)

        for tech in sp.technology_stack:
            tests.update(TECH_TEST_MAP.get(tech, []))

        tests.update(AUTH_TEST_MAP.get(sp.auth_model, []))
        tests.update(API_TEST_MAP.get(sp.api_structure, []))

        return sorted(tests)
