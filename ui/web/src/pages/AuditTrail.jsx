import { useEffect, useState } from "react";
import { api } from "../api";

export default function AuditTrail() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAuditTrail()
      .then(setEvents)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading...</div>;

  const violations = events.filter(e => e.event_type === "SCOPE_VIOLATION");
  const checks = events.filter(e => e.event_type === "AUTHORIZATION_CHECK");

  return (
    <div>
      <h1>Audit Trail</h1>

      <div className="card-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <span className="label">Total Events</span>
          <span className="value">{events.length}</span>
        </div>
        <div className="stat-card">
          <span className="label">Auth Checks</span>
          <span className="value" style={{ color: "var(--green)" }}>{checks.length}</span>
        </div>
        <div className="stat-card">
          <span className="label">Scope Violations</span>
          <span className="value" style={{ color: "var(--red)" }}>{violations.length}</span>
        </div>
      </div>

      {events.length === 0 ? (
        <div className="empty">No audit events recorded.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event</th>
                <th>Target</th>
                <th>Domain</th>
                <th>In Scope</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {events.slice().reverse().map((e, i) => (
                <tr key={i}>
                  <td style={{ whiteSpace: "nowrap", fontSize: 12 }}>{fmtTs(e.timestamp)}</td>
                  <td>
                    <span className={`badge ${e.event_type === "SCOPE_VIOLATION" ? "scope-violation" : "scope-ok"}`}>
                      {e.event_type === "SCOPE_VIOLATION" ? "VIOLATION" : "AUTH CHECK"}
                    </span>
                  </td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{e.target}</td>
                  <td>{e.domain || "-"}</td>
                  <td>{e.scope_match ? <span style={{ color: "var(--green)" }}>Yes</span> : <span style={{ color: "var(--red)" }}>No</span>}</td>
                  <td>{e.severity ? <span className={`badge ${e.severity.toLowerCase()}`}>{e.severity}</span> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function fmtTs(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return ts; }
}
