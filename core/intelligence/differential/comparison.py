"""
Response comparison primitives shared by the differential, parser-differential,
metamorphic and invariant research engines (spec PHASE 5, Points A/B/C/K/P).

Design goals:
- Pure standard-library. No network, no heavy deps -> unit-testable offline.
- Deterministic. Volatile tokens (CSRF, timestamps, UUIDs, nonces) are
  normalised away before comparison so two "equivalent" responses do not
  diverge just because of a per-request nonce.
- Evidence-driven. Every divergence carries both sides' concrete values so a
  human (or the adjudicator) can reproduce and judge it. Nothing here declares
  a vulnerability; it surfaces *anomalies* for the hypothesis pipeline.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── Volatile-token scrubbing ────────────────────────────────────────────
# Patterns that legitimately change between two otherwise-identical responses.
# Replaced with a stable placeholder so body comparison is about *semantics*,
# not per-request entropy.
_VOLATILE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"), "<TIMESTAMP>"),
    (re.compile(r"\b\d{10,13}\b"), "<EPOCH>"),
    (re.compile(r'(?i)(csrf[_-]?token"?\s*[:=]\s*"?)[A-Za-z0-9._\-]+'), r"\1<CSRF>"),
    (re.compile(r'(?i)(nonce"?\s*[:=]\s*"?)[A-Za-z0-9._\-]+'), r"\1<NONCE>"),
    (re.compile(r'(?i)(request[_-]?id"?\s*[:=]\s*"?)[A-Za-z0-9._\-]+'), r"\1<REQID>"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"), "<JWT>"),
]

# Response headers whose value is expected to vary per request and must be
# excluded from header-set comparison.
_VOLATILE_HEADERS = {
    "date", "expires", "age", "set-cookie", "etag", "last-modified",
    "x-request-id", "x-correlation-id", "x-trace-id", "cf-ray", "x-amz-cf-id",
    "content-length", "keep-alive", "x-runtime", "x-response-time", "report-to",
}


def normalize_body(body: str, max_len: int = 8192) -> str:
    """Scrub volatile tokens and collapse whitespace for stable comparison."""
    if not body:
        return ""
    scrubbed = body[:max_len]
    for pattern, repl in _VOLATILE_PATTERNS:
        scrubbed = pattern.sub(repl, scrubbed)
    # Collapse runs of whitespace so pretty-print differences don't register.
    scrubbed = re.sub(r"\s+", " ", scrubbed).strip()
    return scrubbed


def body_similarity(a: str, b: str) -> float:
    """Ratio in [0.0, 1.0] of how similar two (normalised) bodies are."""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


@dataclass(frozen=True)
class ResponseSnapshot:
    """Immutable, comparable view of a single HTTP response."""
    label: str
    status: int
    body: str
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def normalized_body(self) -> str:
        return normalize_body(self.body)

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.normalized_body.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def length(self) -> int:
        return len(self.body or "")

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v.split(";")[0].strip().lower()
        return ""

    def stable_headers(self) -> Dict[str, str]:
        """Header set with volatile headers removed, keys lowercased."""
        return {
            k.lower(): v
            for k, v in self.headers.items()
            if k.lower() not in _VOLATILE_HEADERS
        }


@dataclass
class Divergence:
    """A single observed difference between two responses.

    ``kind`` is one of: status, body, length, content_type, header, reflection,
    timing. ``severity`` is an *observation* weight (info/low/medium), never a
    confirmed-vulnerability rating.
    """
    kind: str
    a_label: str
    b_label: str
    detail: str
    a_value: str = ""
    b_value: str = ""
    severity: str = "info"

    def to_dict(self) -> Dict[str, str]:
        return {
            "kind": self.kind,
            "a_label": self.a_label,
            "b_label": self.b_label,
            "detail": self.detail,
            "a_value": str(self.a_value)[:256],
            "b_value": str(self.b_value)[:256],
            "severity": self.severity,
        }


def compare_snapshots(
    a: ResponseSnapshot,
    b: ResponseSnapshot,
    *,
    similarity_floor: float = 0.98,
    timing_ratio: float = 4.0,
    timing_floor_ms: float = 40.0,
) -> List[Divergence]:
    """Return every material difference between two responses.

    ``similarity_floor`` — normalised bodies below this ratio are "materially
    different". ``timing_ratio``/``timing_floor_ms`` — a timing divergence is
    only reported when the slower response is both ``timing_ratio``x slower and
    the gap exceeds ``timing_floor_ms`` (guards against noise on fast calls).
    """
    out: List[Divergence] = []

    if a.status != b.status:
        # Same status *class* (both 2xx / both 4xx) is a weaker signal than a
        # class crossing (e.g. 200 vs 403 => authz/parse divergence).
        class_crossing = (a.status // 100) != (b.status // 100)
        out.append(Divergence(
            kind="status", a_label=a.label, b_label=b.label,
            detail="status code differs" + (" (class crossing)" if class_crossing else ""),
            a_value=str(a.status), b_value=str(b.status),
            severity="medium" if class_crossing else "low",
        ))

    sim = body_similarity(a.normalized_body, b.normalized_body)
    if sim < similarity_floor:
        out.append(Divergence(
            kind="body", a_label=a.label, b_label=b.label,
            detail=f"response bodies differ (similarity={sim:.2f})",
            a_value=f"hash={a.body_hash} len={a.length}",
            b_value=f"hash={b.body_hash} len={b.length}",
            severity="low",
        ))

    if a.content_type and b.content_type and a.content_type != b.content_type:
        out.append(Divergence(
            kind="content_type", a_label=a.label, b_label=b.label,
            detail="content-type differs",
            a_value=a.content_type, b_value=b.content_type, severity="low",
        ))

    ah, bh = a.stable_headers(), b.stable_headers()
    security_headers = {
        "content-security-policy", "x-frame-options", "x-content-type-options",
        "strict-transport-security", "access-control-allow-origin",
    }
    for hk in security_headers:
        av, bv = ah.get(hk), bh.get(hk)
        if av != bv:
            out.append(Divergence(
                kind="header", a_label=a.label, b_label=b.label,
                detail=f"security header '{hk}' differs",
                a_value=av or "<absent>", b_value=bv or "<absent>", severity="low",
            ))

    slow, fast = (a, b) if a.elapsed_ms >= b.elapsed_ms else (b, a)
    if (fast.elapsed_ms > 0 and slow.elapsed_ms >= fast.elapsed_ms * timing_ratio
            and (slow.elapsed_ms - fast.elapsed_ms) >= timing_floor_ms):
        out.append(Divergence(
            kind="timing", a_label=a.label, b_label=b.label,
            detail="response time differs materially",
            a_value=f"{a.elapsed_ms:.0f}ms", b_value=f"{b.elapsed_ms:.0f}ms",
            severity="info",
        ))

    return out


def all_equivalent(snapshots: List[ResponseSnapshot], **kwargs) -> bool:
    """True when every snapshot is pairwise-equivalent to the first."""
    if len(snapshots) < 2:
        return True
    first = snapshots[0]
    return all(not compare_snapshots(first, s, **kwargs) for s in snapshots[1:])
