import { useEffect, useState } from "react";
import { api } from "../api";

export default function AuditTrail() {
  const [events, setEvents] = useState([]);
  const [execLog, setExecLog] = useState([]);
  const [poc, setPoc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("audit");

  useEffect(() => {
    Promise.all([
      api.getAuditTrail().catch(() => []),
      api.getExecutionLog().catch(() => []),
      api.getPoc().catch(() => null),
    ]).then(([a, e, p]) => { setEvents(a); setExecLog(e); setPoc(p); })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading...</div>;

  const violations = events.filter(e => e.event_type === "SCOPE_VIOLATION");
  const checks = events.filter(e => e.event_type === "AUTHORIZATION_CHECK");

  return (
    <div>
      <h1>Audit Trail</h1>

      <div className="card-grid" style={{ marginBottom: 16 }}>
        <div className="stat-card">
          <span className="label">Audit Events</span>
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
        <div className="stat-card">
          <span className="label">Exec Actions</span>
          <span className="value" style={{ color: "var(--cyan)" }}>{execLog.length}</span>
        </div>
      </div>

      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={`tab ${tab === "audit" ? "active" : ""}`} onClick={() => setTab("audit")}>
          Audit Trail ({events.length})
        </button>
        <button className={`tab ${tab === "exec" ? "active" : ""}`} onClick={() => setTab("exec")}>
          Execution Log ({execLog.length})
        </button>
        {poc && Object.keys(poc).length > 0 && (
          <button className={`tab ${tab === "poc" ? "active" : ""}`} onClick={() => setTab("poc")}>
            PoC Scripts
          </button>
        )}
      </div>

      {tab === "audit" && (
        events.length === 0 ? (
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
        )
      )}

      {tab === "exec" && (
        execLog.length === 0 ? (
          <div className="empty">No execution log entries.</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Timestamp</th><th>Action</th><th>Params</th><th>Result</th><th>Hash</th></tr>
              </thead>
              <tbody>
                {execLog.slice().reverse().map((e, i) => (
                  <tr key={i}>
                    <td style={{ whiteSpace: "nowrap", fontSize: 12 }}>{fmtTs(e.timestamp)}</td>
                    <td style={{ fontWeight: 600 }}>{e.action || "-"}</td>
                    <td style={{ fontSize: 11, fontFamily: "var(--mono)", maxWidth: 250, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {typeof e.params === "object" ? JSON.stringify(e.params) : e.params || "-"}
                    </td>
                    <td style={{ fontSize: 12 }}>{typeof e.result === "object" ? JSON.stringify(e.result).slice(0, 80) : (e.result || "-")}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>{e.hash ? e.hash.slice(0, 12) + "..." : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {tab === "poc" && poc && (
        <div>
          {poc.summary && (
            <div className="card">
              <h3>PoC Summary</h3>
              <pre className="code-block" style={{ whiteSpace: "pre-wrap" }}>{poc.summary}</pre>
            </div>
          )}
          {poc.py && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>Python Reproduce Script</h3>
              <pre className="code-block" style={{ whiteSpace: "pre-wrap", maxHeight: 500, overflow: "auto" }}>{poc.py}</pre>
            </div>
          )}
          {poc.sh && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>Shell Reproduce Script</h3>
              <pre className="code-block" style={{ whiteSpace: "pre-wrap", maxHeight: 500, overflow: "auto" }}>{poc.sh}</pre>
            </div>
          )}
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
