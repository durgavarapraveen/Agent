import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { parseTs } from "../components/utils";

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
        <div className="empty">No scans found. Run Neo to generate results.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Domain</th>
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
                  <td style={{ color: "var(--text-h)", fontWeight: 500, whiteSpace: "nowrap", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis" }} title={s.target}>{s.target}</td>
                  <td>
                    {s.domain ? (
                      <span title={s.domain} style={{
                        display: "inline-block", maxWidth: 150, whiteSpace: "nowrap",
                        overflow: "hidden", textOverflow: "ellipsis", verticalAlign: "middle",
                        padding: "2px 9px", borderRadius: 999, fontSize: 12, fontWeight: 500,
                        background: "rgba(99,102,241,0.12)", color: "var(--accent)",
                        textTransform: "capitalize",
                      }}>{shortDomain(s.domain)}</span>
                    ) : <span style={{ color: "var(--text-dim)" }}>-</span>}
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>
                    <div style={{ fontWeight: 600, color: "var(--text-h)" }}>{fmtTime(s.timestamp)}</div>
                    <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{fmtDay(s.timestamp)}</div>
                  </td>
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

function shortDomain(d) {
  if (!d) return "-";
  // Verbose LLM label ("E-Commerce (Online Juice Shop …)") → keep the part before
  // the parenthesis; canonical keys ("ecommerce") pass through. Cap the length.
  let label = String(d).split("(")[0].replace(/_/g, " ").trim();
  if (label.length > 20) label = label.slice(0, 20).trim() + "…";
  return label;
}

function fmtTime(ts) {
  if (!ts) return "-";
  try { return new Date(parseTs(ts)).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

function fmtDay(ts) {
  if (!ts) return "";
  try { return new Date(parseTs(ts)).toLocaleDateString(); }
  catch { return ""; }
}

function fmtDur(s) {
  if (!s) return "-";
  s = Math.round(s);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (sec || parts.length === 0) parts.push(`${sec}s`);
  return parts.join(" ");
}
