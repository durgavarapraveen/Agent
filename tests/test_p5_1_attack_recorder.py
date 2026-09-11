"""Phase 5.1 — attack narrative with browser recording."""
from __future__ import annotations

from core.reporting.attack_recorder import (
    AttackRecorder,
    attack_recordings_html,
)


def test_manual_steps_narrative_and_html():
    rec = AttackRecorder("f1", "Auth bypass to admin", severity="critical")
    rec.add_step("Navigate to", "https://app.test/admin", note="no auth challenge")
    rec.add_step("Send request to", "https://app.test/api/users", method="GET",
                 response="200", note="returns all users")
    recording = rec.build()

    narrative = recording.narrative()
    assert narrative[0].startswith("1.")
    assert "admin" in narrative[0]
    assert "no auth challenge" in narrative[0]
    assert len(narrative) == 2

    html = rec.render_html()
    assert "Attack narrative" in html
    assert "CRITICAL" in html
    assert "app.test/api/users" in html


def test_html_escaping():
    rec = AttackRecorder("f2", "XSS <script>", severity="high")
    rec.add_step("Send request to", "https://app.test/q?x=<script>alert(1)</script>",
                 request="GET /q?x=<script>")
    html = rec.render_html()
    assert "<script>alert(1)</script>" not in html  # escaped
    assert "&lt;script&gt;" in html


def test_video_embedded_when_present():
    rec = AttackRecorder("f3", "RCE", severity="critical")
    rec.add_step("Navigate to", "https://app.test/upload")
    rec.video_path = "evidence/f3.webm"
    html = rec.render_html()
    assert "<video" in html and "evidence/f3.webm" in html


def test_from_browser_worker():
    from core.browser.browser_worker import BrowserWorker

    worker = BrowserWorker()
    worker.start_session() if hasattr(worker, "start_session") else None
    worker.record_navigation("https://app.test/login", 200)
    worker.record_request("https://app.test/api/login", "POST")
    worker.record_response("https://app.test/api/login", 200)

    rec = AttackRecorder("f4", "Login flow").from_browser_worker(worker)
    recording = rec.build()
    assert len(recording.steps) == 3
    actions = [s.action for s in recording.steps]
    assert "Navigate to" in actions
    assert "Send request to" in actions


def test_attack_recordings_html_block():
    r1 = AttackRecorder("f1", "A").build()
    assert attack_recordings_html([]) == ""
    block = attack_recordings_html([r1])
    assert "Attack Narratives" in block


def test_screenshot_and_request_response_rendered():
    rec = AttackRecorder("f5", "SSRF", severity="high")
    rec.add_step("Send request to", "https://app.test/fetch", method="POST",
                 request="POST /fetch url=http://169.254.169.254",
                 response="200 metadata", screenshot="shots/ssrf.png")
    html = rec.render_html()
    assert "shots/ssrf.png" in html
    assert "169.254.169.254" in html
    assert "metadata" in html
