import { useEffect, useState } from "react";
import { api, createPoller } from "../api";

// Watchdog / budget governor (§26/§39/§46). Live, global, LLM-independent.
// Shows budget consumption + an external kill switch.
function Meter({ label, used, max, unit = "" }) {
  const pct = max ? Math.min(100, (used / max) * 100) : 0;
  const color = pct > 90 ? "#ff3355" : pct > 70 ? "#ffaa00" : "#33cc77";
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
        <span style={{ color: "var(--text-dim)" }}>{label}</span>
        <span style={{ fontFamily: "var(--mono)" }}>{used}{unit} / {max}{unit}</span>
      </div>
      <div style={{ height: 8, borderRadius: 4, background: "var(--bg-elev)", overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color }} />
      </div>
    </div>
  );
}

export default function WatchdogPanel() {
  const [wd, setWd] = useState(null);
  const [killing, setKilling] = useState(false);

  useEffect(() => {
    const poll = createPoller(() => api.getWatchdog(), (d) => { if (d) setWd(d); }, 5000);
    return () => poll.stop();
  }, []);

  async function onKill() {
    if (!window.confirm("Trigger the external kill switch? This halts the active scan immediately.")) return;
    setKilling(true);
    try { await api.killScan("kill via dashboard"); } catch { /* ignore */ }
    finally { setKilling(false); }
  }

  if (!wd) {
    return <div style={{ color: "var(--text-dim)", padding: 16 }}>Watchdog not reporting (no active scan process).</div>;
  }

  const b = wd.budget || {};
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="card">
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
          <span style={{
            padding: "3px 10px", borderRadius: 4, fontSize: 12, fontWeight: 700,
            background: wd.killed ? "#ff3355" : "#33cc77", color: "#000",
          }}>{wd.killed ? "KILLED" : "RUNNING"}</span>
          <span style={{ color: "var(--text-dim)", fontSize: 13 }}>elapsed {wd.elapsed_s}s</span>
          <button className="btn btn-sm" disabled={killing || wd.killed}
                  onClick={onKill}
                  style={{ marginLeft: "auto", background: "#ff3355", color: "#000", fontWeight: 700 }}>
            {killing ? "Killing…" : "Kill switch"}
          </button>
        </div>
        <Meter label="Requests" used={wd.requests || 0} max={b.max_requests || 0} />
        <Meter label="Runtime" used={Math.round(wd.elapsed_s || 0)} max={Math.round(b.max_runtime_s || 0)} unit="s" />
        <Meter label="Bandwidth" used={wd.bandwidth_mb || 0} max={b.max_bandwidth_mb || 0} unit="MB" />
        <Meter label="LLM cost" used={wd.llm_cost || 0} max={b.max_llm_cost || 0} unit="$" />
        <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>
          <span>Browser sessions: {wd.browser_sessions || 0} / {b.max_browser_sessions || 0}</span>
          <span>Max impact: <b>{b.max_impact || "POC"}</b></span>
        </div>
      </div>
    </div>
  );
}
