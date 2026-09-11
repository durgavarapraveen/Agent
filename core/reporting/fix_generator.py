"""Phase 5.2 — AI-generated fix code.

For each finding, produce a concrete remediation: detect the target's
language/framework (Server / X-Powered-By headers, stack traces, file
extensions), then emit framework-specific fix code. Deterministic templates
cover the common (vuln class × framework) combinations and are always available;
the LLM refines or fills gaps when present. In grey-box mode (source available)
it produces a unified diff for the vulnerable file.

LLM is injectable and optional, so this is fully unit-testable — and Python
fixes are validated with ``compile()`` in the tests.
"""
from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Stack:
    language: str = "unknown"
    framework: str = "unknown"


# Header / stack-trace / extension signals → (language, framework)
_HEADER_SIGNALS = [
    ("x-powered-by", "express", ("javascript", "express")),
    ("x-powered-by", "php", ("php", "php")),
    ("x-powered-by", "asp.net", ("csharp", "aspnet")),
    ("x-powered-by", "next.js", ("javascript", "nextjs")),
    ("server", "gunicorn", ("python", "flask")),
    ("server", "werkzeug", ("python", "flask")),
    ("server", "django", ("python", "django")),
]
_TRACE_SIGNALS = [
    # Framework-specific signals first; generic language signals last so a
    # Django traceback isn't classified as bare Python (→ flask default).
    ("django.", ("python", "django")),
    ("flask", ("python", "flask")),
    ("org.springframework", ("java", "spring")),
    ("microsoft.aspnetcore", ("csharp", "aspnet")),
    ("laravel", ("php", "laravel")),
    ("node_modules", ("javascript", "express")),
    ("traceback (most recent call last)", ("python", "")),
    ("java.lang.", ("java", "")),
]
_EXT_SIGNALS = {".php": ("php", "php"), ".aspx": ("csharp", "aspnet"),
                ".jsp": ("java", "spring"), ".py": ("python", ""), ".rb": ("ruby", "rails")}

# Deterministic fix snippets keyed by (vuln_class, framework). Python snippets
# are syntactically valid modules; others are idiomatic snippets.
FIX_TEMPLATES: Dict[tuple, str] = {
    ("sqli", "django"): (
        "# Use the ORM or parameterized queries — never string-format SQL.\n"
        "from django.db import connection\n\n"
        "def get_user(user_id):\n"
        "    with connection.cursor() as cursor:\n"
        "        cursor.execute('SELECT * FROM users WHERE id = %s', [user_id])\n"
        "        return cursor.fetchone()\n"),
    ("sqli", "flask"): (
        "# Parameterize the query; do not use f-strings/%.\n"
        "def get_user(db, user_id):\n"
        "    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()\n"),
    ("sqli", "express"): (
        "// Use placeholders, never string concatenation.\n"
        "db.query('SELECT * FROM users WHERE id = ?', [userId], (err, rows) => { /* ... */ });\n"),
    ("sqli", "spring"): (
        "// Use a PreparedStatement / bound parameters.\n"
        "@Query(\"SELECT u FROM User u WHERE u.id = :id\")\n"
        "User findById(@Param(\"id\") Long id);\n"),
    ("xss", "express"): (
        "// Set security headers and encode output.\n"
        "const helmet = require('helmet');\n"
        "app.use(helmet());\n"
        "// Escape user data before rendering: res.send(escapeHtml(userInput));\n"),
    ("xss", "django"): (
        "# Django autoescapes by default — never use |safe or mark_safe on user input.\n"
        "from django.utils.html import escape\n\n"
        "def render_comment(comment):\n"
        "    return escape(comment)\n"),
    ("bola", "django"): (
        "# Enforce object-level ownership on every access.\n"
        "from django.core.exceptions import PermissionDenied\n\n"
        "def get_order(request, order_id):\n"
        "    order = Order.objects.get(pk=order_id)\n"
        "    if order.owner_id != request.user.id:\n"
        "        raise PermissionDenied\n"
        "    return order\n"),
    ("bola", "spring"): (
        "// Enforce object ownership with method security.\n"
        "@PreAuthorize(\"#order.owner == authentication.name\")\n"
        "public Order getOrder(Order order) { return order; }\n"),
    ("auth_bypass", "django"): (
        "# Require authentication/permission on the view.\n"
        "from django.contrib.auth.decorators import permission_required\n\n"
        "@permission_required('app.view_admin', raise_exception=True)\n"
        "def admin_view(request):\n"
        "    ...\n"),
    ("auth_bypass", "spring"): (
        "// Restrict the endpoint to authorized roles.\n"
        "@PreAuthorize(\"hasRole('ADMIN')\")\n"
        "public ResponseEntity<?> adminOnly() { /* ... */ }\n"),
    ("security_headers", "express"): (
        "const helmet = require('helmet');\n"
        "app.use(helmet());  // sets X-Frame-Options, CSP, HSTS, etc.\n"),
    ("csrf", "django"): (
        "# Keep CsrfViewMiddleware enabled and use {% csrf_token %} in forms.\n"
        "from django.views.decorators.csrf import csrf_protect\n\n"
        "@csrf_protect\n"
        "def submit(request):\n"
        "    ...\n"),
}

_GENERIC_FIX = {
    "sqli": "Use parameterized queries / an ORM; never build SQL from untrusted input.",
    "xss": "Contextually encode all user output; set a strict Content-Security-Policy.",
    "bola": "Enforce object-level authorization: verify the caller owns the resource.",
    "auth_bypass": "Require authentication and role checks on every protected endpoint.",
    "ssrf": "Validate/allowlist outbound URLs; block internal ranges and metadata IPs.",
    "security_headers": "Add X-Frame-Options, CSP, HSTS, X-Content-Type-Options.",
    "csrf": "Require and validate anti-CSRF tokens on state-changing requests.",
}


def detect_stack(headers: Optional[Dict[str, str]] = None, body: str = "",
                 file_extensions: Optional[List[str]] = None) -> Stack:
    headers = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    for hname, needle, (lang, fw) in _HEADER_SIGNALS:
        if needle in headers.get(hname, ""):
            return Stack(lang, fw)
    low = (body or "").lower()
    for needle, (lang, fw) in _TRACE_SIGNALS:
        if needle in low:
            return Stack(lang, fw or _default_fw(lang))
    for ext in (file_extensions or []):
        if ext.lower() in _EXT_SIGNALS:
            lang, fw = _EXT_SIGNALS[ext.lower()]
            return Stack(lang, fw or _default_fw(lang))
    return Stack()


def _default_fw(lang: str) -> str:
    return {"python": "flask", "javascript": "express", "java": "spring"}.get(lang, "unknown")


def _vuln_class(finding: Dict[str, Any]) -> str:
    return str(finding.get("vuln_class") or finding.get("type") or finding.get("category") or "").lower()


class FixGenerator:

    def __init__(self, llm: Any = None):
        self._llm = llm

    def generate_fix(self, finding: Dict[str, Any], stack: Optional[Stack] = None) -> Dict[str, Any]:
        stack = stack or Stack()
        vclass = _vuln_class(finding)
        code = FIX_TEMPLATES.get((vclass, stack.framework))
        source = "template"
        if not code:
            code = _GENERIC_FIX.get(vclass)
            source = "generic" if code else "none"
        return {"vuln_class": vclass, "language": stack.language,
                "framework": stack.framework, "fix_code": code or "",
                "source": source}

    async def generate_fix_llm(self, finding: Dict[str, Any], stack: Optional[Stack] = None) -> Dict[str, Any]:
        stack = stack or Stack()
        base = self.generate_fix(finding, stack)
        if self._llm is None:
            return base
        prompt = (f"Generate a code fix for {_vuln_class(finding)} in "
                  f"{stack.language}/{stack.framework}. The vulnerable endpoint is "
                  f"{finding.get('url', finding.get('endpoint',''))}. The vulnerability is: "
                  f"{finding.get('description', finding.get('title',''))}. "
                  "Return ONLY the fixed code as JSON {\"code\": \"...\"}.")
        try:
            data = await self._llm.generate_json(prompt)
            code = (data or {}).get("code")
            if code:
                return {**base, "fix_code": code, "source": "llm"}
        except Exception as e:
            logger.warning("fix_generator: LLM fix failed (%s)", e)
        return base

    def generate_diff(self, file_path: str, original: str, fixed: str) -> str:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True), fixed.splitlines(keepends=True),
            fromfile=f"a/{file_path}", tofile=f"b/{file_path}")
        return "".join(diff)

    def annotate_findings(self, findings: List[Dict[str, Any]],
                          stack: Optional[Stack] = None) -> List[Dict[str, Any]]:
        for f in findings:
            fix = self.generate_fix(f, stack)
            if fix["fix_code"]:
                f["fix"] = fix["fix_code"]
                f["fix_source"] = fix["source"]
        return findings
