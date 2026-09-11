"""Phase 4.4 — mobile (APK/IPA) backend analysis."""
from __future__ import annotations

import plistlib

from core.discovery.ipa_analyzer import IPAAnalyzer, parse_info_plist
from core.discovery.mobile_analyzer import (
    MobileAnalyzer,
    detect_cert_pinning,
    extract_secrets,
    extract_urls,
    inject_endpoints_into_context,
    parse_android_manifest,
)

MANIFEST = """<?xml version="1.0"?>
<manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
  <application>
    <activity android:name=".Main">
      <intent-filter>
        <data android:scheme="myapp" android:host="pay"/>
      </intent-filter>
    </activity>
  </application>
</manifest>"""

SMALI = """
const-string v0, "https://api.example.com/v1/users"
const-string v1, "https://api.example.com/v1/pay"
const-string v2, "AIzaSyA1234567890abcdefghijklmnopqrstuv0"
const-string v3, "api_key=abcdef1234567890ABCDEF"
new-instance CertificatePinner
"""


def test_extract_urls_and_secrets():
    assert "https://api.example.com/v1/users" in extract_urls(SMALI)
    types = {s["type"] for s in extract_secrets(SMALI)}
    assert "google_api_key" in types
    assert "generic_api_key" in types


def test_parse_android_manifest():
    man = parse_android_manifest(MANIFEST)
    assert man["package"] == "com.example.app"
    assert "android.permission.INTERNET" in man["permissions"]
    assert "myapp://pay" in man["deeplinks"]


def test_detect_cert_pinning():
    assert detect_cert_pinning(SMALI)
    assert not detect_cert_pinning("nothing here")


def test_apk_analyze_extracted(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (tmp_path / "classes.smali").write_text(SMALI, encoding="utf-8")
    analysis = MobileAnalyzer().analyze_extracted(str(tmp_path))
    assert analysis.package == "com.example.app"
    assert "https://api.example.com/v1/pay" in analysis.endpoints
    assert analysis.cert_pinning is True
    assert "myapp://pay" in analysis.deeplinks
    eps = analysis.to_endpoints()
    assert all(e["source"] == "mobile_apk" for e in eps)


def test_apk_analyze_missing_tools_returns_empty(tmp_path):
    # No apktool/jadx installed here → analyze() returns an empty analysis, no crash.
    fake_apk = tmp_path / "app.apk"
    fake_apk.write_bytes(b"not a real apk")
    analysis = MobileAnalyzer().analyze(str(fake_apk))
    assert analysis.endpoints == []


def test_parse_info_plist():
    plist = {
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myiosapp", "fb123"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
                                   "NSExceptionDomains": {"insecure.example.com": {}}},
    }
    info = parse_info_plist(plistlib.dumps(plist))
    assert info["bundle_id"] == "com.example.ios"
    assert "myiosapp://" in info["deeplinks"]
    assert "NSAllowsArbitraryLoads=true" in info["ats_exceptions"]
    assert "insecure.example.com" in info["ats_exceptions"]


def test_inject_endpoints_via_add_endpoints():
    # ctx exposing add_endpoints(endpoints, source=...) — the SharedContext path.
    class Ctx:
        def __init__(self):
            self.added = []
        def add_endpoints(self, eps, source=""):
            self.added.append((eps, source))
    ctx = Ctx()
    n = inject_endpoints_into_context(ctx, ["https://api.test/a", "https://api.test/b"], "mobile_apk")
    assert n == 2
    eps, source = ctx.added[0]
    assert source == "mobile_apk"
    assert eps[0]["url"] == "https://api.test/a" and eps[0]["source"] == "mobile_apk"


def test_inject_endpoints_fallback_to_list():
    class Ctx:
        endpoints = []
    ctx = Ctx()
    n = inject_endpoints_into_context(ctx, ["https://api.test/x"])
    assert n == 1
    assert ctx.endpoints[0]["url"] == "https://api.test/x"


def test_inject_endpoints_empty():
    class Ctx:
        endpoints = []
    assert inject_endpoints_into_context(Ctx(), []) == 0


def test_ipa_analyze_extracted(tmp_path):
    payload = tmp_path / "Payload" / "App.app"
    payload.mkdir(parents=True)
    plist = {"CFBundleIdentifier": "com.example.ios",
             "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myiosapp"]}]}
    (payload / "Info.plist").write_bytes(plistlib.dumps(plist))
    (payload / "config.json").write_text('{"api":"https://api.example.com/ios"}', encoding="utf-8")
    analysis = IPAAnalyzer().analyze_extracted(str(tmp_path))
    assert analysis.bundle_id == "com.example.ios"
    assert "myiosapp://" in analysis.deeplinks
    assert "https://api.example.com/ios" in analysis.endpoints
