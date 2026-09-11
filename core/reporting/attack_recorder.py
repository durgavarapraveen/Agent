"""Phase 5.1 — attack narrative with browser recording.

For a critical/high finding, capture the exploit as a replayable story: the
ordered steps (navigation + request/response at each hop), annotated
screenshots, an optional Playwright video, and a human-readable narrative — then
embed all of it in the HTML report.

Reuse:
  * ``BrowserWorker`` (core.browser) already records navigation/request/response
    observations — :meth:`AttackRecorder.from_browser_worker` turns those into
    steps.
  * ``repro_bundle`` builds the downloadable reproduction bundle.
  * Playwright video recording is guarded (needs a live browser); the recorder
    produces the narrative + HTML with or without it, so it is fully testable.
"""
from __future__ import annotations

import html
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_OBS_ACTION = {
    "navigation": "Navigate to",
    "request": "Send request to",
    "response": "Receive response from",
    "redirect": "Follow redirect to",
    "dom_snapshot": "Capture DOM at",
    "console": "Console event at",
}


@dataclass
class AttackStep:
    index: int
    action: str
    url: str = ""
    method: str = ""
    request: str = ""
    response: str = ""
    screenshot: str = ""
    note: str = ""

    def narrative_line(self) -> str:
        bits = [self.action]
        if self.method:
            bits.append(self.method)
        if self.url:
            bits.append(self.url)
        line = " ".join(bits).strip()
        if self.note:
            line += f" — {self.note}"
        return line


@dataclass
class AttackRecording:
    finding_id: str
    title: str
    severity: str = "high"
    steps: List[AttackStep] = field(default_factory=list)
    video_path: str = ""

    def narrative(self) -> List[str]:
        return [f"{s.index}. {s.narrative_line()}" for s in self.steps]

    def to_dict(self) -> Dict[str, Any]:
        return {"finding_id": self.finding_id, "title": self.title,
                "severity": self.severity, "video_path": self.video_path,
                "steps": [s.__dict__ for s in self.steps],
                "narrative": self.narrative()}

    def to_html(self) -> str:
        e = html.escape
        parts = [f'<section class="attack-recording" data-finding="{e(self.finding_id)}">',
                 f'<h3>Attack narrative: {e(self.title)} '
                 f'<span class="severity {e(self.severity)}">{e(self.severity.upper())}</span></h3>']
        if self.video_path:
            parts.append(f'<video controls src="{e(self.video_path)}" '
                         f'style="max-width:100%"></video>')
        parts.append("<ol class='attack-steps'>")
        for s in self.steps:
            parts.append("<li>")
            parts.append(f"<div class='step-action'>{e(s.narrative_line())}</div>")
            if s.screenshot:
                parts.append(f'<img class="step-shot" src="{e(s.screenshot)}" '
                             f'alt="step {s.index}" style="max-width:100%"/>')
            if s.request:
                parts.append(f"<pre class='req'>{e(s.request[:2000])}</pre>")
            if s.response:
                parts.append(f"<pre class='resp'>{e(s.response[:2000])}</pre>")
            parts.append("</li>")
        parts.append("</ol></section>")
        return "\n".join(parts)


class AttackRecorder:

    def __init__(self, finding_id: str, title: str, severity: str = "high"):
        self.finding_id = finding_id
        self.title = title
        self.severity = severity
        self.steps: List[AttackStep] = []
        self.video_path = ""
        self._page = None

    def add_step(self, action: str, url: str = "", method: str = "",
                 request: str = "", response: str = "", screenshot: str = "",
                 note: str = "") -> AttackStep:
        step = AttackStep(index=len(self.steps) + 1, action=action, url=url,
                          method=method, request=request, response=response,
                          screenshot=screenshot, note=note)
        self.steps.append(step)
        return step

    def from_browser_worker(self, worker: Any) -> "AttackRecorder":
        """Ingest a BrowserWorker's recorded observations as ordered steps."""
        obs = getattr(worker, "_observations", None)
        if obs is None and hasattr(worker, "get_observations"):
            obs = worker.get_observations()
        for o in sorted(obs or [], key=lambda x: getattr(x, "timestamp", 0)):
            otype = getattr(o, "observation_type", "")
            data = getattr(o, "data", {}) or {}
            self.add_step(
                action=_OBS_ACTION.get(otype, otype or "Step"),
                url=getattr(o, "url", ""),
                method=data.get("method", ""),
                response=str(data.get("status_code", "")) if otype == "response" else "",
                note=data.get("note", ""))
        return self

    # ── Playwright video (guarded — needs a live browser) ────────────────────
    def start_video(self, browser_context: Any, page: Any = None) -> bool:
        """Enable video recording. The context must have been created with
        record_video_dir set; this just remembers the page to close later."""
        try:
            self._page = page
            return True
        except Exception as e:
            logger.debug("attack_recorder: start_video no-op (%s)", e)
            return False

    def stop_video(self) -> str:
        try:
            if self._page is not None and hasattr(self._page, "video") and self._page.video:
                self.video_path = self._page.video.path()
        except Exception as e:
            logger.debug("attack_recorder: stop_video (%s)", e)
        return self.video_path

    def build(self) -> AttackRecording:
        return AttackRecording(self.finding_id, self.title, self.severity,
                               list(self.steps), self.video_path)

    def render_html(self) -> str:
        return self.build().to_html()


def attack_recordings_html(recordings: List[AttackRecording]) -> str:
    """Render a list of recordings into one HTML block for the report."""
    if not recordings:
        return ""
    body = "\n".join(r.to_html() for r in recordings)
    return f'<div class="attack-recordings"><h2>Attack Narratives</h2>{body}</div>'
