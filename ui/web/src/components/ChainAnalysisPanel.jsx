import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 2.1 — exploit-chain narratives, end-to-end CVSS, finding re-scoring.
const SEV_COLOR = { critical: "var(--red, #ff3355)", high: "#ff8800", medium: "#ffaa00", low: "#88bbff" };

export default function ChainAnalysisPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getChainAnalysis(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Analyzing chains…</div>;

  const narratives = data?.narratives || [];
  const upgrades = data?.rescore?.upgrades || [];

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 14, alignItems: "baseline" }}>
        <span style={{ fontWeight: 700, letterSpacing: 1 }}>{data?.chain_count || 0} CHAINS</span>
        <span style={{ color: "var(--text-dim)", fontSize: 13 }}>
          {data?.rescore?.upgraded_count || 0} finding(s) re-scored by chain membership
        </span>
      </div>

      {upgrades.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <h3>Severity re-scored by chain membership</h3>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Finding</th><th>From</th><th>To</th><th>Chain</th></tr></thead>
              <tbody>
                {upgrades.map((u, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{u.finding}</td>
                    <td><span className={`badge ${u.from}`}>{(u.from || "").toUpperCase()}</span></td>
                    <td><span className={`badge ${u.to}`}>{(u.to || "").toUpperCase()}</span></td>
                    <td style={{ fontSize: 12, color: "var(--text-dim)" }}>{u.chain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {narratives.length === 0 && (
        <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
          No multi-step chains synthesized. Chains form when findings enable one another
          (e.g. SSRF → internal access, cred leak → auth bypass).
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {narratives.map((n, i) => {
          const color = SEV_COLOR[(n.severity || "").toLowerCase()] || "var(--text-dim)";
          return (
            <div key={i} style={{ border: `1px solid ${color}`, borderRadius: 6, padding: 16, background: "var(--bg-elev)" }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
                <span style={{ padding: "3px 10px", borderRadius: 3, fontSize: 11, fontWeight: 700, background: color, color: "#000" }}>
                  {(n.severity || "?").toUpperCase()}
                </span>
                <span style={{ fontWeight: 700, color: "var(--text-h)" }}>{n.chain_id}</span>
                <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", color }}>CVSS {n.cvss}</span>
              </div>
              <ol style={{ margin: 0, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 6 }}>
                {(n.steps || []).map((s, j) => (
                  <li key={j} style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.5 }}>{s}</li>
                ))}
              </ol>
            </div>
          );
        })}
      </div>
    </div>
  );
}
