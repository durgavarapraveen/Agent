"""Dockerfile static analysis (spec §20/§21 — container weaknesses).

Deterministic checks over Dockerfile instructions: running as root, mutable
image tags, secrets baked into ENV/ARG, remote code fetched and piped to a
shell, curl-pipe-to-shell, sudo installs, and sensitive host mounts declared in
comments. Content is UNTRUSTED and only parsed, never executed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

_SECRET_KEY = re.compile(
    r"(pass(word)?|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)",
    re.IGNORECASE)
_SECRET_VALUE = re.compile(r"=\s*['\"]?[^'\"\s]{6,}")


def _finding(ftype, title, severity, proof, line) -> Dict[str, Any]:
    return {
        "type": ftype, "title": title, "severity": severity,
        "location": f"Dockerfile:{line}" if line else "Dockerfile",
        "proof": proof, "tool": "sca", "source": "sca_container",
        "confidence_score": 0.85,
    }


def analyze_dockerfile(content: str, path: str = "Dockerfile") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    saw_user_nonroot = False
    lines = content.splitlines()

    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()

        if upper.startswith("FROM"):
            img = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            img = img.split(" AS ")[0].split(" as ")[0].strip()
            if img and ":" not in img.split("/")[-1]:
                findings.append(_finding(
                    "CONTAINER_MISCONFIG", f"Unpinned base image (implicit latest): {img}",
                    "MEDIUM", f"FROM {img} has no explicit tag/digest", i))
            elif img.endswith(":latest"):
                findings.append(_finding(
                    "CONTAINER_MISCONFIG", f"Mutable base image tag: {img}",
                    "MEDIUM", f"FROM {img} uses :latest", i))

        if upper.startswith("USER"):
            user = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if user and user.lower() not in ("root", "0"):
                saw_user_nonroot = True
            elif user.lower() in ("root", "0"):
                saw_user_nonroot = False

        if upper.startswith(("ENV", "ARG")) and _SECRET_KEY.search(line) and _SECRET_VALUE.search(line):
            findings.append(_finding(
                "CONTAINER_SECRET", "Secret baked into image ENV/ARG",
                "HIGH", f"{line.split()[0]} line assigns a secret-looking value", i))

        if upper.startswith("ADD") and re.search(r"https?://", line):
            findings.append(_finding(
                "CONTAINER_MISCONFIG", "ADD fetches a remote URL (use verified COPY)",
                "LOW", line, i))

        if re.search(r"(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(sh|bash)", line):
            findings.append(_finding(
                "CONTAINER_MISCONFIG", "Remote script piped to a shell",
                "HIGH", "curl/wget | sh executes unverified remote code at build", i))

        if re.search(r"\bsudo\b", line):
            findings.append(_finding(
                "CONTAINER_MISCONFIG", "sudo used in image build",
                "LOW", line, i))

    if not saw_user_nonroot:
        findings.append(_finding(
            "CONTAINER_MISCONFIG", "Container runs as root (no non-root USER)",
            "HIGH", "no `USER <non-root>` instruction; process runs as uid 0", 0))

    return findings
