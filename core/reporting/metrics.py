"""
Monitoring & Metrics (Phase 4, Module 3)

Tracks the engagement in real time:
  - Success rates (agents, exploits, chains)
  - Timing / performance metrics
  - Failure alerts
  - A live self-refreshing HTML dashboard + JSON snapshot

Time is injected via a `clock` callable (defaults to time.time) so the module
stays testable and deterministic.
"""

import json
import logging
import time
import threading
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class MetricsTracker:
    """Collects counters/timers and renders a live dashboard."""

    def __init__(self, target: str = "", out_dir: str = "reports",
                 clock: Callable[[], float] = time.time,
                 alert_cb: Optional[Callable[[str, Dict], None]] = None):
        self.target = target
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(exist_ok=True)
        self._clock = clock
        self._alert_cb = alert_cb
        self._lock = threading.Lock()
        self.start = clock()

        self.counters: Dict[str, int] = defaultdict(int)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.events: List[Dict] = []
        self.alerts: List[Dict] = []
        self._open_spans: Dict[str, float] = {}

    # ── recording ──

    def incr(self, name: str, n: int = 1):
        with self._lock:
            self.counters[name] += n

    def span_start(self, key: str):
        self._open_spans[key] = self._clock()

    def span_end(self, key: str, bucket: str) -> float:
        t0 = self._open_spans.pop(key, None)
        if t0 is None:
            return 0.0
        dt = self._clock() - t0
        with self._lock:
            self.timers[bucket].append(dt)
        return dt

    def record_event(self, kind: str, name: str, success: bool, detail: str = ""):
        with self._lock:
            self.events.append({
                "t": round(self._clock() - self.start, 2),
                "kind": kind, "name": name, "success": bool(success),
                "detail": str(detail)[:200],
            })
            self.counters[f"{kind}_total"] += 1
            self.counters[f"{kind}_{'ok' if success else 'fail'}"] += 1
        if not success:
            self.alert(f"{kind} failed: {name}", {"detail": detail})

    def alert(self, message: str, data: Dict = None):
        entry = {"t": round(self._clock() - self.start, 2), "message": message,
                 "data": data or {}}
        with self._lock:
            self.alerts.append(entry)
        logger.warning(f"[Metrics][ALERT] {message}")
        if self._alert_cb:
            try:
                self._alert_cb(message, data or {})
            except Exception:       # noqa: BLE001
                pass

    # ── derived ──

    def success_rate(self, kind: str) -> float:
        ok = self.counters.get(f"{kind}_ok", 0)
        total = self.counters.get(f"{kind}_total", 0)
        return round(100.0 * ok / total, 1) if total else 0.0

    def timing_summary(self) -> Dict[str, Dict]:
        out = {}
        for bucket, vals in self.timers.items():
            if vals:
                out[bucket] = {
                    "count": len(vals), "total": round(sum(vals), 2),
                    "avg": round(sum(vals) / len(vals), 2),
                    "max": round(max(vals), 2), "min": round(min(vals), 2),
                }
        return out

    def snapshot(self) -> Dict:
        with self._lock:
            return {
                "target": self.target,
                "elapsed_sec": round(self._clock() - self.start, 1),
                "counters": dict(self.counters),
                "success_rates": {
                    k: self.success_rate(k)
                    for k in ("agent", "exploit", "chain", "tool")
                },
                "timing": self.timing_summary(),
                "alerts": list(self.alerts[-20:]),
                "recent_events": list(self.events[-25:]),
            }

    # ── outputs ──

    def write_json(self, name: str = "dashboard.json") -> str:
        path = self.out_dir / name
        path.write_text(json.dumps(self.snapshot(), indent=2, default=str),
                        encoding="utf-8")
        return str(path)

    def write_dashboard(self, name: str = "dashboard.html", refresh: int = 5) -> str:
        s = self.snapshot()
        rate_rows = "".join(
            f"<div class='kpi'><div class='v'>{v}%</div><div class='l'>{k} success</div></div>"
            for k, v in s["success_rates"].items())
        alert_rows = "".join(
            f"<li>[{a['t']}s] {a['message']}</li>" for a in reversed(s["alerts"])
        ) or "<li class='muted'>No alerts.</li>"
        event_rows = "".join(
            f"<tr><td>{e['t']}s</td><td>{e['kind']}</td><td>{e['name']}</td>"
            f"<td class='{'ok' if e['success'] else 'fail'}'>"
            f"{'OK' if e['success'] else 'FAIL'}</td><td>{e['detail']}</td></tr>"
            for e in reversed(s["recent_events"]))
        timing_rows = "".join(
            f"<tr><td>{b}</td><td>{d['count']}</td><td>{d['avg']}s</td>"
            f"<td>{d['max']}s</td></tr>" for b, d in s["timing"].items())
        return self._write(name, f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="{refresh}">
<title>Pentest Dashboard — {self.target}</title>
<style>
 body{{font-family:Segoe UI,Roboto,sans-serif;background:#0e1726;color:#e6edf5;margin:0}}
 header{{padding:16px 24px;background:#12233b}} h1{{font-size:18px;margin:0}}
 main{{padding:20px 24px;max-width:1000px;margin:0 auto}}
 .kpis{{display:flex;gap:14px;flex-wrap:wrap}}
 .kpi{{background:#16273f;border:1px solid #22364f;border-radius:8px;padding:14px 18px;min-width:120px}}
 .kpi .v{{font-size:26px;font-weight:700}} .kpi .l{{font-size:12px;opacity:.7}}
 section{{background:#12203a;border:1px solid #22364f;border-radius:8px;padding:14px 18px;margin:16px 0}}
 table{{width:100%;border-collapse:collapse;font-size:12px}}
 td,th{{padding:5px 8px;border-bottom:1px solid #22364f;text-align:left}}
 .ok{{color:#4caf50}} .fail{{color:#ff6b6b}} .muted{{opacity:.6}} ul{{font-size:13px}}
</style></head><body>
<header><h1>Live Pentest Dashboard — {self.target}</h1>
 <div style="font-size:12px;opacity:.7">elapsed {s['elapsed_sec']}s · auto-refresh {refresh}s</div></header>
<main>
 <div class="kpis">{rate_rows}
  <div class='kpi'><div class='v'>{s['counters'].get('vuln_total',0)}</div><div class='l'>vulnerabilities</div></div>
  <div class='kpi'><div class='v'>{len(s['alerts'])}</div><div class='l'>alerts</div></div></div>
 <section><h3>Alerts</h3><ul>{alert_rows}</ul></section>
 <section><h3>Timing</h3><table><tr><th>Bucket</th><th>Count</th><th>Avg</th><th>Max</th></tr>{timing_rows}</table></section>
 <section><h3>Recent Events</h3><table><tr><th>t</th><th>Kind</th><th>Name</th><th>Status</th><th>Detail</th></tr>{event_rows}</table></section>
</main></body></html>""")

    def _write(self, name: str, content: str) -> str:
        path = self.out_dir / name
        path.write_text(content, encoding="utf-8")
        return str(path)
