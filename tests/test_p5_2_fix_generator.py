"""Phase 5.2 — AI-generated fix code."""
from __future__ import annotations

from core.reporting.fix_generator import FixGenerator, Stack, detect_stack


def test_detect_stack_from_headers():
    assert detect_stack(headers={"X-Powered-By": "Express"}).framework == "express"
    assert detect_stack(headers={"Server": "gunicorn/20"}).language == "python"


def test_detect_stack_from_stacktrace():
    s = detect_stack(body="Traceback (most recent call last): ... django.db.utils")
    assert s.language == "python"
    assert s.framework == "django"
    assert detect_stack(body="at Object.<anonymous> (/app/node_modules/x)").language == "javascript"
    assert detect_stack(body="org.springframework.web...").framework == "spring"


def test_detect_stack_from_extension():
    assert detect_stack(file_extensions=[".php"]).language == "php"
    assert detect_stack(file_extensions=[".aspx"]).framework == "aspnet"


def test_template_fix_python_is_syntactically_valid():
    gen = FixGenerator()
    fix = gen.generate_fix({"vuln_class": "sqli"}, Stack("python", "django"))
    assert fix["source"] == "template"
    assert "cursor.execute" in fix["fix_code"]
    # Python fix must compile.
    compile(fix["fix_code"], "<fix>", "exec")


def test_template_fix_express_helmet():
    fix = FixGenerator().generate_fix({"type": "security_headers"}, Stack("javascript", "express"))
    assert "helmet" in fix["fix_code"]


def test_bola_and_auth_bypass_fixes():
    gen = FixGenerator()
    bola = gen.generate_fix({"vuln_class": "bola"}, Stack("python", "django"))
    assert "PermissionDenied" in bola["fix_code"]
    compile(bola["fix_code"], "<fix>", "exec")
    spring = gen.generate_fix({"vuln_class": "auth_bypass"}, Stack("java", "spring"))
    assert "@PreAuthorize" in spring["fix_code"]


def test_generic_fallback_when_no_template():
    fix = FixGenerator().generate_fix({"vuln_class": "ssrf"}, Stack("go", "gin"))
    assert fix["source"] == "generic"
    assert "outbound" in fix["fix_code"].lower() or "metadata" in fix["fix_code"].lower()


def test_generate_diff():
    gen = FixGenerator()
    diff = gen.generate_diff("app.py", "q = 'SELECT %s' % x\n", "q = 'SELECT ?'  # param\n")
    assert diff.startswith("---") or "@@" in diff
    assert "app.py" in diff


def test_annotate_findings():
    gen = FixGenerator()
    findings = [{"vuln_class": "sqli"}, {"vuln_class": "xss"}]
    gen.annotate_findings(findings, Stack("python", "django"))
    assert all("fix" in f for f in findings)
    assert findings[0]["fix_source"] == "template"


async def test_llm_fix_path():
    class _LLM:
        async def generate_json(self, prompt, **kw):
            return {"code": "SAFE_FIX_CODE()"}

    gen = FixGenerator(llm=_LLM())
    fix = await gen.generate_fix_llm({"vuln_class": "unknown_class"}, Stack("go", "gin"))
    assert fix["fix_code"] == "SAFE_FIX_CODE()"
    assert fix["source"] == "llm"
