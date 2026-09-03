import { useEffect, useState } from "react";
import { api } from "../api";

export default function Compare() {
  const [scans, setScans] = useState([]);
  const [scanA, setScanA] = useState("");
  const [scanB, setScanB] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.getScans().then(setScans).catch(() => {});
  }, []);

  const handleCompare = async () => {
    if (!scanA || !scanB) return;
    if (scanA === scanB) { setError("Select two different scans"); return; }
    setError("");
    setLoading(true);
    try {
      const data = await api.compareScans(scanA, scanB);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>Scan Comparison</h1>

      <div className="card">
        <h3>Select Scans to Compare</h3>
        <div style={{ display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div className="form-group">
            <label>Scan A (baseline)</label>
            <select value={scanA} onChange={(e) => setScanA(e.target.value)}
              style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13, minWidth: 260 }}>
              <option value="">Select scan...</option>
              {scans.map(s => (
                <option key={s.scan_id} value={s.scan_id}>{s.target} — {fmtDate(s.timestamp)} ({s.total_vulns} vulns)</option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Scan B (latest)</label>
            <select value={scanB} onChange={(e) => setScanB(e.target.value)}
              style={{ padding: "8px 12px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13, minWidth: 260 }}>
              <option value="">Select scan...</option>
              {scans.map(s => (
                <option key={s.scan_id} value={s.scan_id}>{s.target} — {fmtDate(s.timestamp)} ({s.total_vulns} vulns)</option>
              ))}
            </select>
          </div>
          <button className="btn btn-primary" onClick={handleCompare} disabled={loading || !scanA || !scanB}>
            {loading ? "Comparing..." : "Compare"}
          </button>
        </div>
        {error && <div className="error-msg" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {result && (
        <>
          <div className="card-grid" style={{ marginTop: 16 }}>
            <CompareCard label="Scan A" data={result.scan_a} />
            <CompareCard label="Scan B" data={result.scan_b} />
          </div>

          <div className="two-col" style={{ marginTop: 16 }}>
            <div className="card">
              <h3 style={{ color: "var(--red)" }}>New in Scan B ({result.new_in_b.length})</h3>
              {result.new_in_b.length === 0 ? (
                <div style={{ fontSize: 13, color: "var(--text-dim)" }}>No new vulnerabilities</div>
              ) : (
                <ul style={{ paddingLeft: 16, fontSize: 13 }}>
                  {result.new_in_b.map((t, i) => <li key={i} style={{ marginBottom: 4, color: "var(--red)" }}>{t}</li>)}
                </ul>
              )}
            </div>
            <div className="card">
              <h3 style={{ color: "var(--green)" }}>Fixed in Scan B ({result.fixed_in_b.length})</h3>
              {result.fixed_in_b.length === 0 ? (
                <div style={{ fontSize: 13, color: "var(--text-dim)" }}>No fixed vulnerabilities</div>
              ) : (
                <ul style={{ paddingLeft: 16, fontSize: 13 }}>
                  {result.fixed_in_b.map((t, i) => <li key={i} style={{ marginBottom: 4, color: "var(--green)" }}>{t}</li>)}
                </ul>
              )}
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>Unchanged ({result.common.length})</h3>
            {result.common.length === 0 ? (
              <div style={{ fontSize: 13, color: "var(--text-dim)" }}>No common vulnerabilities</div>
            ) : (
              <div style={{ maxHeight: 200, overflowY: "auto" }}>
                {result.common.map((t, i) => (
                  <div key={i} style={{ padding: "4px 0", fontSize: 12, borderBottom: "1px solid var(--border)", color: "var(--text)" }}>{t}</div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function CompareCard({ label, data }) {
  return (
    <div className="stat-card" style={{ gap: 8 }}>
      <span className="label">{label}</span>
      <span style={{ fontSize: 14, color: "var(--text-h)", fontWeight: 600, fontFamily: "var(--mono)" }}>{data.target}</span>
      <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{fmtDate(data.timestamp)}</span>
      <div style={{ display: "flex", gap: 12, fontSize: 12, marginTop: 4 }}>
        <span>Total: <strong>{data.total_vulns}</strong></span>
        <span>Confirmed: <strong style={{ color: "var(--green)" }}>{data.confirmed}</strong></span>
      </div>
      <div style={{ display: "flex", gap: 8, fontSize: 11, marginTop: 4 }}>
        {data.severity_counts.CRITICAL > 0 && <span className="badge critical">{data.severity_counts.CRITICAL} C</span>}
        {data.severity_counts.HIGH > 0 && <span className="badge high">{data.severity_counts.HIGH} H</span>}
        {data.severity_counts.MEDIUM > 0 && <span className="badge medium">{data.severity_counts.MEDIUM} M</span>}
        {data.severity_counts.LOW > 0 && <span className="badge low">{data.severity_counts.LOW} L</span>}
        {data.severity_counts.INFO > 0 && <span className="badge info">{data.severity_counts.INFO} I</span>}
      </div>
    </div>
  );
}

function fmtDate(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}
