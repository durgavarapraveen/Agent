from __future__ import annotations

from dataclasses import dataclass
from time import time
from typing import Dict, List, Optional


# Source reliability: how often the source lies.
SOURCE_RELIABILITY: Dict[str, float] = {
    "nuclei": 0.9, "nuclei_jsonl": 0.95,
    "sqlmap": 0.9, "dalfox": 0.85,
    "nmap": 0.9, "masscan": 0.75,
    "whatweb": 0.8, "httpx": 0.85, "wafw00f": 0.75,
    "nikto": 0.55,           # noisy
    "ffuf": 0.7, "gobuster": 0.7, "feroxbuster": 0.7,
    "manual": 0.6, "llm_inference": 0.4,
    "regex_stdout": 0.5,
}

# Parser reliability: how well we extract the fact from the tool output.
PARSER_RELIABILITY: Dict[str, float] = {
    "json": 0.95, "jsonl": 0.95, "structured": 0.9,
    "regex": 0.6, "line_scrape": 0.5, "heuristic": 0.4,
}


@dataclass
class ConfidenceInputs:
    source: str = ""
    parser: str = "regex"
    validated: bool = False
    corroborations: int = 0          # independent tools that saw the same thing
    age_seconds: float = 0.0
    llm_score: Optional[float] = None  # LLM's own self-reported certainty


def compute(inp: ConfidenceInputs) -> float:
    src = SOURCE_RELIABILITY.get((inp.source or "").lower(), 0.5)
    par = PARSER_RELIABILITY.get((inp.parser or "").lower(), 0.5)
    validation = 1.0 if inp.validated else 0.5
    # Corroboration lifts confidence but with diminishing returns.
    corr = 1.0 - (0.5 ** max(0, inp.corroborations))
    corr = 0.5 + 0.5 * corr        # base 0.5, saturates to 1.0
    # Recency decay: half-life 24h.
    hl = 24 * 3600.0
    recency = 0.5 ** (max(0.0, inp.age_seconds) / hl)
    recency = 0.5 + 0.5 * recency
    base = src * par * validation * corr * recency
    if inp.llm_score is not None:
        base = 0.7 * base + 0.3 * max(0.0, min(1.0, inp.llm_score))
    return max(0.0, min(1.0, base))


def label(conf: float) -> str:
    if conf >= 0.85:
        return "high"
    if conf >= 0.6:
        return "medium"
    if conf >= 0.35:
        return "low"
    return "very_low"
