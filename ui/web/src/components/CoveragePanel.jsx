import { useEffect, useState } from "react";
import { api } from "../api";

// Coverage ledger (§23/§24): what was actually TESTED vs BLOCKED/ERRORED/SKIPPED.
// The whole point: absence of a finding is NOT proof of safety — UNKNOWN ≠ CLEAN.
const STATE_COLOR = {
  TESTED: "#33cc77", BLOCKED: "#ffaa00", ERRORED: "#ff3355", SKIPPED: "#88aacc",
};

export default function CoveragePanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getCoverage(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading coverage…</div>;

  const ledger = data?.ledger || {};
  const counts = ledger.counts || {};
  const completeness = Math.round((ledger.completeness || 0) * 100);
  const errored = ledger.errored_cells || [];
  const surface = data?.surface || {};
  const oos = data?.discovered_out_of_scope || [];
  const sinks = data?.dom_sinks || {};
  const total = ledger.total_cells || Object.values(counts).reduce((a, b) => a + b, 0);

  if (!total && !surface.surfaces) {
    return (
      <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
        No coverage ledger recorded for this scan yet. It populates once the surface
        dispatcher runs (crawl → classify → test).
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Completeness headline */}
      <div className="card">
        <div style={{ display: "flex", gap: 16, alignItems: "baseline", flexWrap: "wrap" }}>
          <span style={{ fontWeight: 700, fontSize: 22 }}>{completeness}%</span>
          <span style={{ color: "var(--text-dim)" }}>of {total} (surface × class) cells verified</span>
          <span style={{ marginLeft: "auto", color: "var(--text-dim)", fontSize: 12 }}>
            {surface.surfaces || 0} surfaces · {surface.points || 0} injection points
          </span>
        </div>
        <div style={{ display: "flex", height: 12, borderRadius: 6, overflow: "hidden", marginTop: 12, background: "var(--bg-elev)" }}>
          {["TESTED", "BLOCKED", "ERRORED", "SKIPPED"].map((s) => {
            const n = counts[s] || 0;
            const pct = total ? (n / total) * 100 : 0;
            return pct > 0 ? (
              <div key={s} title={`${s}: ${n}`} style={{ width: `${pct}%`, background: STATE_COLOR[s] }} />
            ) : null;
          })}
        </div>
        <div style={{ display: "flex", gap: 16, marginTop: 10, flexWrap: "wrap" }}>
          {["TESTED", "BLOCKED", "ERRORED", "SKIPPED"].map((s) => (
            <span key={s} style={{ fontSize: 12, color: "var(--text-dim)" }}>
              <span style={{ display: "inline-block", width: 10, height: 10, borderRadius: 2, background: STATE_COLOR[s], marginRight: 6 }} />
              {s} {counts[s] || 0}
            </span>
          ))}
        </div>
        <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-dim)" }}>
          ⚠ UNKNOWN ≠ CLEAN — BLOCKED / ERRORED / SKIPPED cells were <b>not</b> verified.
        </div>
      </div>

      {/* Errored cells — the silent-skip guard */}
      {errored.length > 0 && (
        <div className="card">
          <h3>Errored cells ({errored.length}) — not tested, needs attention</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Class</th><th>Point</th><th>Surface</th><th>Reason</th></tr></thead>
              <tbody>
                {errored.slice(0, 100).map((e, i) => (
                  <tr key={i}>
                    <td><span className="badge">{e.class}</span></td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{e.point}</td>
                    <td style={{ fontSize: 12, color: "var(--text-dim)", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis" }}>{e.surface}</td>
                    <td style={{ fontSize: 12 }}>{e.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Discovered but out of scope — containment visibility */}
      {oos.length > 0 && (
        <div className="card">
          <h3>Discovered but OUT OF SCOPE ({oos.length})</h3>
          <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>
            Hosts the crawl/discovery found that the immutable authorization contract refused — recorded, never tested.
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {oos.map((h, i) => (
              <span key={i} style={{ fontFamily: "var(--mono)", fontSize: 12, padding: "2px 8px", border: "1px solid var(--border)", borderRadius: 4 }}>{h}</span>
            ))}
          </div>
        </div>
      )}

      {/* Surface kinds + DOM sinks */}
      {(surface.kinds || Object.keys(sinks).length > 0) && (
        <div className="card">
          <h3>Surfaces</h3>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 8 }}>
            {Object.entries(surface.kinds || {}).map(([k, n]) => (
              <span key={k} className="badge">{k}: {n}</span>
            ))}
          </div>
          {Object.keys(sinks).length > 0 && (
            <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
              Client-side DOM sinks on {Object.keys(sinks).length} page(s) (XSS surface).
            </div>
          )}
        </div>
      )}
    </div>
  );
}
