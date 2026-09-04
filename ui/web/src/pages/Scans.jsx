import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api.getScans()
      .then(setScans)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div>
      <h1>Scan History</h1>
      {scans.length === 0 ? (
        <div className="empty">No scans found. Run AntiGravity to generate results.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Target</th>
                <th>Date</th>
                <th>Duration</th>
                <th>Agents</th>
                <th>Vulns</th>
                <th>Critical</th>
                <th>High</th>
                <th>Confirmed</th>
                <th>Rejected</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.scan_id} className="click-row" onClick={() => navigate(`/scans/${s.scan_id}`)}>
                  <td style={{ fontFamily: "var(--mono)", fontSize: "11px", color: "var(--accent)" }}>{s.scan_id}</td>
                  <td style={{ color: "var(--text-h)", fontWeight: 500 }}>{s.target}</td>
                  <td style={{ whiteSpace: "nowrap" }}>{fmtDate(s.timestamp)}</td>
                  <td>{fmtDur(s.duration_seconds)}</td>
                  <td>{s.agents_used}</td>
                  <td style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{s.total_vulns}</td>
                  <td>{s.severity_counts?.CRITICAL > 0 ? <span className="badge critical">{s.severity_counts.CRITICAL}</span> : "-"}</td>
                  <td>{s.severity_counts?.HIGH > 0 ? <span className="badge high">{s.severity_counts.HIGH}</span> : "-"}</td>
                  <td>{s.status_counts?.CONFIRMED > 0 ? <span className="badge confirmed">{s.status_counts.CONFIRMED}</span> : "-"}</td>
                  <td>{s.status_counts?.REJECTED > 0 ? <span className="badge rejected">{s.status_counts.REJECTED}</span> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
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

function fmtDur(s) {
  if (!s) return "-";
  const m = Math.floor(s / 60);
  const sec = Math.round(s % 60);
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}
