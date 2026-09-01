"""
Unit tests for ErrorTranslator.
Simulates 10 different tool failure scenarios and verifies actionable recommendations.
"""

from core.common.error_translator import ErrorTranslator, ErrorCategory


def test_sslscan_econnrefused():
    err = ErrorTranslator.translate("sslscan", "Connection refused (ECONNREFUSED)")
    assert err["category"] == ErrorCategory.PERMANENT.value
    assert "Port not responding" in err["cause"]
    assert "HTTP-only" in err["recommendation"]
    assert err["alternative_tool"] == "curl"
    assert err["should_retry"] is False


def test_sslscan_timeout():
    err = ErrorTranslator.translate("sslscan", "Timeout after 30s waiting for socket")
    assert err["category"] == ErrorCategory.TIMEOUT.value
    assert err["should_retry"] is True
    assert "httpx" in err["alternative_tool"]


def test_nmap_sudo_missing():
    err = ErrorTranslator.translate("nmap", "sudo: command not found")
    assert err["category"] == ErrorCategory.PERMANENT.value
    assert "-sT" in err["recommendation"]
    assert err["should_retry"] is False


def test_openssl_handshake_failure():
    err = ErrorTranslator.translate("openssl", "SSL_ERROR_CONNECT_FAILURE: handshake failure")
    assert err["category"] == ErrorCategory.PERMANENT.value
    assert "TLS handshake failed" in err["cause"]


def test_waf_blocked_403():
    err = ErrorTranslator.translate("httpx", "403 Forbidden - WAF Security Blocked")
    assert err["category"] == ErrorCategory.PERMANENT.value
    assert "WAF" in err["cause"]
    assert err["alternative_tool"] == "whatweb"


def test_missing_binary():
    err = ErrorTranslator.translate("subfinder", "subfinder: command not found")
    assert err["category"] == ErrorCategory.ENVIRONMENT.value
    assert "Python-native fallback" in err["recommendation"]


def test_sqlmap_non_injectable():
    err = ErrorTranslator.translate("sqlmap", "all tested parameters appear to be not injectable")
    assert err["category"] == ErrorCategory.PERMANENT.value
    assert err["alternative_tool"] == "dalfox"


def test_nmap_host_down():
    err = ErrorTranslator.translate("nmap", "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn")
    assert err["category"] == ErrorCategory.ENVIRONMENT.value
    assert "-Pn" in err["recommendation"]
    assert err["should_retry"] is True


def test_formatted_report_structure():
    err = ErrorTranslator.translate("curl", "could not resolve host: invalid.example.com")
    report = err["formatted_report"]
    assert "[WARN] TOOL_FAILED: curl" in report
    assert "Error: ENVIRONMENT" in report
    assert "Recommendation:" in report


def test_generic_unknown_error():
    err = ErrorTranslator.translate("custom_tool", "Uncaught runtime error at line 42")
    assert err["category"] == ErrorCategory.PERMANENT.value
    assert "Tool execution failure" in err["cause"]
