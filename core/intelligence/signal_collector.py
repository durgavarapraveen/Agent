"""Pα Signal Collector — extracts attack-surface signals from recon data."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ReconSignal:
    source: str          # "header", "response_body", "endpoint", "error", "technology", "config"
    category: str = ""   # auto-classified attack surface (filled by SignalClassifier)
    raw_data: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5


class SignalClassifier:
    SURFACE_PATTERNS: Dict[str, List[str]] = {
        "graphql": ["graphql", "playground", "__schema", "introspection", "/graphql"],
        "websocket": ["ws://", "wss://", "socket.io", "upgrade: websocket", "websocket"],
        "oauth": ["oauth", "/authorize", "callback", "client_id", "redirect_uri", "openid"],
        "xml_processing": ["xml", "soap", "wsdl", "dtd", "<!entity", "text/xml", "application/xml"],
        "template_engine": ["jinja", "twig", "freemarker", "velocity", "{{", "${", "mako", "thymeleaf"],
        "serialization": ["serialize", "pickle", "marshal", "objectinputstream", "ysoserial",
                          "base64", "viewstate", "__viewstate"],
        "ssrf_surface": ["url=", "redirect=", "proxy=", "fetch=", "load=", "img=", "src=",
                         "dest=", "uri=", "path=", "continue=", "window=", "next=", "data=",
                         "reference=", "site=", "html=", "val=", "validate=", "domain=",
                         "callback=", "return=", "page=", "feed=", "host=", "port=", "to=",
                         "out=", "view=", "dir="],
        "cache_layer": ["x-cache", "cf-cache", "age:", "varnish", "x-varnish", "x-cache-hits",
                        "x-proxy-cache", "x-served-by"],
        "mail_system": ["smtp", "sendmail", "mail(", "x-mailer", "contact", "feedback"],
        "file_inclusion": ["include=", "file=", "path=", "template=", "page=", "doc=",
                           "folder=", "root=", "style=", "pdf=", "log="],
        "ldap": ["ldap://", "ldaps://", "cn=", "dc=", "ou="],
        "nosql": ["mongodb", "couchdb", "$where", "$gt", "$ne", "$regex", "mongoose"],
        "grpc": ["grpc", "protobuf", "application/grpc"],
        "api_gateway": ["x-amzn-apigateway", "kong", "apigee", "rate-limit",
                        "x-ratelimit", "retry-after"],
        "cicd_exposure": ["jenkins", "gitlab-ci", "github-actions", ".env", "dockerfile",
                          "travis", "circleci", ".git/"],
        "cloud_metadata": ["169.254.169.254", "metadata.google", "100.100.100.200"],
        "cors": ["access-control-allow-origin", "access-control-allow-credentials"],
        "jwt": ["eyj", "jwt", "bearer", "authorization: bearer", "jsonwebtoken"],
        "upload": ["upload", "multipart", "file", "attachment", "content-disposition"],
        "crlf": ["%0d%0a", "\\r\\n", "carriage", "newline"],
        "host_header": ["x-forwarded-host", "x-original-url", "x-rewrite-url"],
        "race_condition": ["quantity", "amount", "balance", "transfer", "coupon",
                           "discount", "vote", "like", "follow"],
    }

    def classify(self, signals: List[ReconSignal]) -> Dict[str, List[ReconSignal]]:
        classified: Dict[str, List[ReconSignal]] = {}
        for sig in signals:
            data_lower = sig.raw_data.lower()
            for surface, patterns in self.SURFACE_PATTERNS.items():
                if any(p in data_lower for p in patterns):
                    sig.category = sig.category or surface
                    classified.setdefault(surface, []).append(sig)
                    break
            if not sig.category:
                sig.category = "unknown"
                classified.setdefault("unknown", []).append(sig)
        return classified


class SignalCollector:
    """Harvests ReconSignals from SharedContext data."""

    def from_headers(self, url: str, headers: Dict[str, str]) -> List[ReconSignal]:
        signals = []
        for name, value in headers.items():
            signals.append(ReconSignal(
                source="header",
                raw_data=f"{name}: {value}",
                context={"url": url, "header_name": name, "header_value": value},
            ))
        return signals

    def from_response(self, url: str, status: int, body: str,
                      headers: Optional[Dict[str, str]] = None) -> List[ReconSignal]:
        signals = []
        if body:
            signals.append(ReconSignal(
                source="response_body",
                raw_data=body[:2000],
                context={"url": url, "status_code": status},
            ))
        if headers:
            signals.extend(self.from_headers(url, headers))
        return signals

    def from_endpoints(self, endpoints: List) -> List[ReconSignal]:
        signals = []
        for ep in endpoints:
            url = ep if isinstance(ep, str) else (ep.get("url", "") if isinstance(ep, dict) else str(ep))
            if not url:
                continue
            signals.append(ReconSignal(
                source="endpoint",
                raw_data=url,
                context={"url": url},
            ))
            # Extract query params as separate signals for SSRF/LFI detection
            if "=" in url:
                signals.append(ReconSignal(
                    source="endpoint_params",
                    raw_data=url.split("?", 1)[-1] if "?" in url else url,
                    context={"url": url, "has_params": True},
                    confidence=0.7,
                ))
        return signals

    def from_errors(self, error_messages: List[str]) -> List[ReconSignal]:
        return [
            ReconSignal(source="error", raw_data=msg[:500], confidence=0.8)
            for msg in error_messages if msg
        ]

    def from_technologies(self, tech_stack: List) -> List[ReconSignal]:
        signals = []
        for tech in tech_stack:
            name = tech if isinstance(tech, str) else (tech.get("name", "") if isinstance(tech, dict) else str(tech))
            signals.append(ReconSignal(
                source="technology",
                raw_data=name,
                context={"technology": name},
                confidence=0.9,
            ))
        return signals

    def from_config_disclosure(self, configs: List[Dict]) -> List[ReconSignal]:
        return [
            ReconSignal(
                source="config",
                raw_data=str(cfg)[:500],
                context=cfg,
                confidence=0.9,
            )
            for cfg in configs
        ]

    def collect_from_ctx(self, ctx) -> List[ReconSignal]:
        """Harvest all available signals from a SharedContextV2 instance."""
        signals = []

        # Endpoints
        eps = getattr(ctx, "endpoints", []) or []
        signals.extend(self.from_endpoints(eps))

        # Technologies
        techs = getattr(ctx, "technologies", []) or []
        signals.extend(self.from_technologies(techs))

        # Headers from ctx
        hdr = getattr(ctx, "headers", {}) or {}
        if hdr:
            signals.extend(self.from_headers(getattr(ctx, "target", ""), hdr))

        # Errors from brain_log
        errors = [line for line in (getattr(ctx, "brain_log", []) or [])
                  if any(kw in line.lower() for kw in ("error", "exception", "traceback", "fail"))]
        signals.extend(self.from_errors(errors[:20]))

        # Secrets / config disclosures
        secrets = getattr(ctx, "secrets", []) or []
        if secrets:
            signals.extend(self.from_config_disclosure(secrets))

        # Tool execution results (look for interesting patterns)
        for exec_rec in (getattr(ctx, "tool_executions", []) or [])[-30:]:
            if isinstance(exec_rec, dict):
                cmd = exec_rec.get("command", "")
                if cmd:
                    signals.append(ReconSignal(
                        source="tool_output",
                        raw_data=cmd[:300],
                        context=exec_rec,
                    ))

        logger.info(f"[SignalCollector] Collected {len(signals)} signals from context")
        return signals
