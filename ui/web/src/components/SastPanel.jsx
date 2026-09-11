import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 4.5 — grey-box SAST↔DAST correlation.
export default function SastPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getSastCorrelation(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading SAST correlation…</div>;

  if (!data?.available) {
    return (
      <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
        No source (SAST) run for this scan. Start a scan with a <strong>source repo/path</strong>
        (Grey-box &amp; Mobile section) to correlate Semgrep findings with runtime results.
      </div>
    );
  }

  const c = data.counts || {};
  const Section = ({ title, items, note, color, render }) => (
    <div className="card" style={{ margin: "0 0 12px" }}>
      <h3 style={{ color }}>{title} ({items.length})</h3>
      {note && <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 8 }}>{note}</div>}
      {items.length === 0 ? <div style={{ color: "var(--text-dim)", fontSize: 12 }}>None</div> : (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>{items.map(render)}</div>
      )}
    </div>
  );

  return (
    <div>
      <div className="card-grid" style={{ marginBottom: 12 }}>
        <div className="stat-card"><span className="label">Confirmed (SAST+DAST)</span>
          <span className="value" style={{ color: "var(--red)" }}>{c.confirmed || 0}</span></div>
        <div className="stat-card"><span className="label">SAST only</span>
          <span className="value" style={{ color: "var(--orange)" }}>{c.sast_only || 0}</span></div>
        <div className="stat-card"><span className="label">DAST only</span>
          <span className="value">{c.dast_only || 0}</span></div>
      </div>

      <Section title="Confirmed — found in source AND at runtime" color="var(--red)"
        items={data.confirmed || []}
        note="Highest confidence: the same vulnerability class correlates in code and live testing."
        render={(f, i) => (
          <div key={i} style={{ fontSize: 12, padding: 8, background: "var(--surface-1, #1a1a2e)", borderRadius: 6 }}>
            <span className="badge critical" style={{ marginRight: 8 }}>{(f.vuln_class || "").toUpperCase()}</span>
            <span style={{ fontFamily: "var(--mono)" }}>{f.sast?.file}:{f.sast?.line}</span>
            <span style={{ color: "var(--text-dim)" }}> ↔ {f.dast?.url}</span>
          </div>
        )} />

      <Section title="SAST only — potential, needs runtime validation" color="var(--orange)"
        items={data.sast_only || []}
        render={(f, i) => (
          <div key={i} style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
            <span className={`badge ${(f.severity || "medium")}`} style={{ marginRight: 8 }}>{(f.vuln_class || "").toUpperCase()}</span>
            {f.file}:{f.line}
          </div>
        )} />

      <Section title="DAST only — confirmed at runtime" color="var(--text-dim)"
        items={data.dast_only || []}
        render={(f, i) => (
          <div key={i} style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
            <span className={`badge ${(f.severity || "info").toLowerCase()}`} style={{ marginRight: 8 }}>{(f.vuln_class || f.type || "").toUpperCase()}</span>
            {f.url || f.location || ""}
          </div>
        )} />
    </div>
  );
}
