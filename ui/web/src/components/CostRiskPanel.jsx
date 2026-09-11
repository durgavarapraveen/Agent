import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 6.1 (LLM cost) + Phase 5.3 (executive dollar risk).
export default function CostRiskPanel({ scanId }) {
  const [cost, setCost] = useState(null);
  const [risk, setRisk] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    Promise.all([api.getScanCost(scanId), api.getScanRisk(scanId)])
      .then(([c, r]) => { if (alive) { setCost(c); setRisk(r); } })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading cost & risk…</div>;

  const usd = (n) => "$" + Number(n || 0).toLocaleString(undefined, { maximumFractionDigits: 0 });
  const usd4 = (n) => "$" + Number(n || 0).toFixed(4);
  const trend = risk?.trend || {};
  const trendColor = trend.direction === "up" ? "var(--red)" : trend.direction === "down" ? "var(--green)" : "var(--text-dim)";

  return (
    <div>
      {/* Executive risk in dollars */}
      <div className="card" style={{ marginBottom: 16 }}>
        <h3>Executive Risk Estimate</h3>
        <div className="card-grid">
          <div className="stat-card">
            <span className="label">Total Portfolio Risk</span>
            <span className="value" style={{ color: "var(--red)" }}>{usd(risk?.total_risk_usd)}</span>
          </div>
          <div className="stat-card">
            <span className="label">Findings Priced</span>
            <span className="value">{risk?.finding_count || 0}</span>
          </div>
          {trend.direction && trend.direction !== "baseline" && (
            <div className="stat-card">
              <span className="label">Trend vs last scan</span>
              <span className="value" style={{ color: trendColor, fontSize: 18 }}>
                {trend.direction === "up" ? "▲" : trend.direction === "down" ? "▼" : "—"} {usd(Math.abs(trend.delta_usd))} ({trend.delta_pct}%)
              </span>
            </div>
          )}
        </div>
        {risk?.top_findings?.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 6 }}>Top cost drivers</div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Finding</th><th>Severity</th><th style={{ textAlign: "right" }}>Est. cost</th></tr></thead>
                <tbody>
                  {risk.top_findings.map((f, i) => (
                    <tr key={i}>
                      <td style={{ color: "var(--text-h)" }}>{f.title}</td>
                      <td><span className={`badge ${(f.severity || "info").toLowerCase()}`}>{(f.severity || "").toUpperCase()}</span></td>
                      <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>{usd(f.dollars)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
        <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-dim)" }}>
          Modeled on IBM "Cost of a Data Breach" methodology (data-type × industry × regulatory × severity). Indicative, not a guarantee.
        </div>
      </div>

      {/* LLM cost */}
      <div className="card">
        <h3>LLM Cost (this scan)</h3>
        <div className="card-grid">
          <div className="stat-card">
            <span className="label">Total Cost</span>
            <span className="value">{usd4(cost?.total_cost_usd)}</span>
          </div>
          <div className="stat-card">
            <span className="label">Requests</span>
            <span className="value">{cost?.requests || 0}</span>
          </div>
          <div className="stat-card">
            <span className="label">Input Tokens</span>
            <span className="value" style={{ fontSize: 18 }}>{(cost?.total_input_tokens || 0).toLocaleString()}</span>
          </div>
          <div className="stat-card">
            <span className="label">Output Tokens</span>
            <span className="value" style={{ fontSize: 18 }}>{(cost?.total_output_tokens || 0).toLocaleString()}</span>
          </div>
        </div>
        {cost?.by_model && Object.keys(cost.by_model).length > 0 && (
          <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-dim)" }}>
            {Object.entries(cost.by_model).map(([model, v]) => (
              <div key={model} style={{ display: "flex", gap: 16, marginBottom: 4 }}>
                <span style={{ fontWeight: 600, color: "var(--text)", minWidth: 220 }}>{model}</span>
                <span>{v.requests} req</span>
                <span>{((v.input_tokens || 0) + (v.output_tokens || 0)).toLocaleString()} tok</span>
                <span>{usd4(v.cost_usd)}</span>
              </div>
            ))}
          </div>
        )}
        {(!cost || cost.requests === 0) && (
          <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>
            No per-scan LLM cost recorded yet (populates as the scan makes model calls).
          </div>
        )}
      </div>
    </div>
  );
}
