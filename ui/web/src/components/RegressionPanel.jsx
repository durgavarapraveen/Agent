import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 3.3 — regression lifecycle (fixed findings that reappeared) + MTTF.
export default function RegressionPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getScanRegression(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading regression data…</div>;

  const byStatus = data?.by_status || {};
  const mttf = data?.mean_time_to_fix_hours || {};
  const regressed = byStatus.regressed || 0;

  return (
    <div>
      <div className="card-grid">
        <div className="stat-card">
          <span className="label">Tracked Findings</span>
          <span className="value">{data?.tracked || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">Regressed</span>
          <span className="value" style={{ color: regressed > 0 ? "var(--red)" : "var(--green)" }}>{regressed}</span>
        </div>
        <div className="stat-card">
          <span className="label">Regression Rate</span>
          <span className="value">{Math.round((data?.regression_rate || 0) * 100)}%</span>
        </div>
        <div className="stat-card">
          <span className="label">Fixed</span>
          <span className="value" style={{ color: "var(--green)" }}>{byStatus.fixed || 0}</span>
        </div>
      </div>

      {Object.keys(mttf).length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Mean Time To Fix (hours, by severity)</h3>
          <div className="pill-row">
            {Object.entries(mttf).map(([sev, hrs]) => (
              <span key={sev} className="pill">
                <span className={`badge ${sev}`} style={{ marginRight: 6 }}>{sev.toUpperCase()}</span>{hrs}h
              </span>
            ))}
          </div>
        </div>
      )}

      {(data?.tracked || 0) === 0 && (
        <div style={{ marginTop: 16, padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
          No regression history yet. Fixed findings are tracked here; if a fixed finding
          reappears on a later scan it is flagged <strong style={{ color: "var(--red)" }}>REGRESSED</strong>.
        </div>
      )}
    </div>
  );
}
