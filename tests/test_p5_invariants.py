"""PHASE 5 — security-invariant engine (offline)."""
from core.intelligence.differential.comparison import ResponseSnapshot
from core.intelligence.invariants import InvariantEngine


def _snap(status, body, headers=None):
    return ResponseSnapshot(label="r", status=status, body=body, headers=headers or {})


def test_stack_trace_leak_flagged():
    body = "Traceback (most recent call last):\n  File app.py line 12"
    viols = InvariantEngine().check(_snap(500, body))
    assert any(v.invariant == "no_stack_trace" and v.severity == "medium" for v in viols)


def test_sql_error_leak_flagged_high():
    body = "You have an error in your SQL syntax near 'foo'"
    viols = InvariantEngine().check(_snap(500, body))
    assert any(v.invariant == "no_sql_error" and v.severity == "high" for v in viols)


def test_path_disclosure_flagged():
    body = "cannot open C:\\inetpub\\wwwroot\\app\\config.php"
    viols = InvariantEngine().check(_snap(200, body))
    assert any(v.invariant == "no_path_disclosure" for v in viols)


def test_server_version_disclosure_flagged():
    viols = InvariantEngine().check(_snap(200, "ok", {"Server": "Apache/2.4.41"}))
    assert any(v.invariant == "no_server_version" for v in viols)


def test_clean_response_no_violations():
    snap = _snap(200, '{"data":[]}', {"Content-Type": "application/json"})
    assert InvariantEngine().check(snap) == []


def test_html_missing_nosniff_flagged_but_present_ok():
    missing = _snap(200, "<html>hi</html>", {"Content-Type": "text/html"})
    present = _snap(200, "<html>hi</html>",
                    {"Content-Type": "text/html", "X-Content-Type-Options": "nosniff"})
    assert any(v.invariant == "html_nosniff" for v in InvariantEngine().check(missing))
    assert not any(v.invariant == "html_nosniff" for v in InvariantEngine().check(present))


def test_failed_auth_session_pair_flagged():
    success = _snap(200, "welcome", {"Set-Cookie": "sessionid=abc; HttpOnly"})
    failure = _snap(401, "bad creds", {"Set-Cookie": "sessionid=zzz; HttpOnly"})
    viol = InvariantEngine.check_auth_pair(success, failure)
    assert viol is not None and viol.severity == "high"


def test_failed_auth_without_session_ok():
    success = _snap(200, "welcome", {"Set-Cookie": "sessionid=abc; HttpOnly"})
    failure = _snap(401, "bad creds", {})
    assert InvariantEngine.check_auth_pair(success, failure) is None


def _names(viols):
    return {v.invariant for v in viols}


def test_html_missing_frame_protection_flagged():
    snap = _snap(200, "<html>hi</html>", {"Content-Type": "text/html"})
    assert "html_frame_protection" in _names(InvariantEngine().check(snap))


def test_html_frame_protection_via_xfo_ok():
    snap = _snap(200, "<html>hi</html>",
                 {"Content-Type": "text/html", "X-Frame-Options": "DENY"})
    assert "html_frame_protection" not in _names(InvariantEngine().check(snap))


def test_html_frame_protection_via_csp_frame_ancestors_ok():
    snap = _snap(200, "<html>hi</html>",
                 {"Content-Type": "text/html",
                  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
    assert "html_frame_protection" not in _names(InvariantEngine().check(snap))


def test_frame_protection_not_flagged_on_json():
    snap = _snap(200, '{"ok":true}', {"Content-Type": "application/json"})
    assert "html_frame_protection" not in _names(InvariantEngine().check(snap))


def _https(status, headers=None):
    return ResponseSnapshot(label="https://t.example/x", status=status,
                            body="ok", headers=headers or {})


def test_https_missing_hsts_flagged():
    assert "https_hsts" in _names(InvariantEngine().check(_https(200)))


def test_https_with_hsts_ok():
    snap = _https(200, {"Strict-Transport-Security": "max-age=31536000"})
    assert "https_hsts" not in _names(InvariantEngine().check(snap))


def test_hsts_not_flagged_without_https_scheme():
    # Plain http:// origin, or a non-URL label: HSTS is meaningless -> silent.
    http_snap = ResponseSnapshot(label="http://t.example/x", status=200, body="ok")
    label_snap = _snap(200, "ok")  # label="r"
    assert "https_hsts" not in _names(InvariantEngine().check(http_snap))
    assert "https_hsts" not in _names(InvariantEngine().check(label_snap))
