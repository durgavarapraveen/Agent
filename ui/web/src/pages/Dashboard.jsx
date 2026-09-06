import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api, createPoller } from "../api";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [active, setActive] = useState(null);
  const [review, setReview] = useState({ summary: {}, manual: [] });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Poll via the shared `createPoller` helper — AbortController + generation
  // counter guarantees that a slow REST response can't overwrite fresher state
  // and that unmount cancels any in-flight request (#087).
  useEffect(() => {
    const p1 = createPoller(
      () => Promise.all([api.getStats(), api.getScans(), api.getActiveScan()]),
      ([s, sc, a]) => { setStats(s); setScans(sc); setActive(a); setLoading(false); },
      8000,
    );
    const p2 = createPoller(
      () => Promise.all([
        api.getReviewQueue().catch(() => ({ summary: {} })),
        api.getReviewManual().catch(() => ({ items: [] })),
      ]),
      ([q, m]) => setReview({ summary: q.summary || {}, manual: m.items || [] }),
      8000,
    );
    return () => { p1.stop(); p2.stop(); };
  }, []);

  if (loading) return <div className="loading">Initializing</div>;

  return (
    <div>
      <div className="page-header">
        <h1>Command Center</h1>
        <button className="btn btn-primary" onClick={() => navigate("/targets")}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
          New Scan
        </button>
      </div>

      {active && <ActiveScanCard scan={active} />}

      {stats && (
        <div className="card-grid">
          <div className="stat-card accent-accent">
            <span className="label">Total Scans</span>
            <span className="value">{stats.total_scans || 0}</span>
          </div>
          <div className="stat-card accent-cyan">
            <span className="label">Unique Targets</span>
            <span className="value">{stats.unique_targets || 0}</span>
          </div>
          <div className="stat-card accent-orange">
            <span className="label">Total Vulns</span>
            <span className="value">{stats.total_vulns || 0}</span>
          </div>
          <div className="stat-card accent-red">
            <span className="label">Critical</span>
            <span className="value">{stats.critical_count || 0}</span>
          </div>
          <div className="stat-card accent-purple">
            <span className="label">High</span>
            <span className="value">{stats.high_count || 0}</span>
          </div>
        </div>
      )}

      <div className="two-col">
        <div className="card">
          <h3>Severity Distribution</h3>
          {stats ? <SeverityDonut stats={stats} /> : <div className="empty">No data</div>}
        </div>
        <div className="card">
          <h3>Quick Stats</h3>
          {stats ? <QuickStats stats={stats} /> : <div className="empty">No data</div>}
        </div>
      </div>

      <ReviewWidget review={review} navigate={navigate} />

      <div className="card" style={{ marginTop: 8 }}>
        <h3>Recent Scans</h3>
        {scans.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">&#9881;</div>
            No scans yet. Add a target to begin.
          </div>
        ) : (
          <div className="table-wrap" style={{ border: "none", boxShadow: "none" }}>
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Date</th>
                  <th>Duration</th>
                  <th>Vulns</th>
                  <th>Critical</th>
                  <th>High</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map(s => (
                  <tr key={s.scan_id} className="click-row" onClick={() => navigate(`/scans/${s.scan_id}`)}>
                    <td style={{ color: "var(--text-h)", fontWeight: 600 }}>{s.target}</td>
                    <td style={{ whiteSpace: "nowrap", fontSize: 12 }}>{fmtDate(s.timestamp)}</td>
                    <td style={{ fontSize: 12, fontFamily: "var(--mono)" }}>{fmtDur(s.duration_seconds)}</td>
                    <td style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{s.total_vulns}</td>
                    <td>{s.severity_counts?.CRITICAL > 0 ? <span className="badge critical">{s.severity_counts.CRITICAL}</span> : <span style={{ color: "var(--text-dim)" }}>0</span>}</td>
                    <td>{s.severity_counts?.HIGH > 0 ? <span className="badge high">{s.severity_counts.HIGH}</span> : <span style={{ color: "var(--text-dim)" }}>0</span>}</td>
                    <td>{s.status_counts?.CONFIRMED > 0 ? <span className="badge confirmed">{s.status_counts.CONFIRMED} confirmed</span> : <span style={{ color: "var(--text-dim)" }}>-</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function ReviewWidget({ review, navigate }) {
  const s = review.summary || {};
  const manual = (review.manual || []).slice(0, 4);
  const nothing = !(s.success || s.needs_manual);

  return (
    <div className="card" style={{ marginTop: 8 }}>
      <div className="flex-between" style={{ alignItems: "center", marginBottom: 4 }}>
        <h3 style={{ margin: 0 }}>Agent Review</h3>
        <button className="btn" style={{ fontSize: 12, padding: "4px 10px" }} onClick={() => navigate("/review")}>
          Open queue &rarr;
        </button>
      </div>
      <p style={{ color: "var(--text-dim)", fontSize: 12, marginTop: 0 }}>
        Confirmed exploits to showcase, and objectives the agent couldn't crack — handed to you.
      </p>

      <div style={{ display: "flex", gap: 12, marginBottom: manual.length ? 16 : 0 }}>
        <div className="stat-card accent-green" style={{ flex: 1, cursor: "pointer" }} onClick={() => navigate("/review")}>
          <span className="label">Confirmed Exploits</span>
          <span className="value" style={{ color: "var(--green)" }}>{s.success || 0}</span>
        </div>
        <div className="stat-card accent-orange" style={{ flex: 1, cursor: "pointer" }} onClick={() => navigate("/review")}>
          <span className="label">Needs Manual Pentest</span>
          <span className="value" style={{ color: "var(--orange, #ea580c)" }}>{s.needs_manual || 0}</span>
        </div>
      </div>

      {nothing ? (
        <div className="empty" style={{ padding: 16 }}>No agent attempts recorded yet.</div>
      ) : manual.length > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <span style={{ fontSize: 11, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.6px", fontWeight: 600 }}>
            Waiting for you
          </span>
          {manual.map((r) => (
            <div key={r.id} className="click-row" onClick={() => navigate("/review")}
              style={{ padding: "10px 12px", borderRadius: 8, background: "var(--surface-2, rgba(255,255,255,0.02))",
                       borderLeft: "3px solid var(--orange, #ea580c)", cursor: "pointer" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}>
                <strong style={{ fontSize: 13 }}>{r.title}</strong>
                <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)", whiteSpace: "nowrap" }}>{r.target}</span>
              </div>
              {r.manual_guidance && (
                <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4,
                              overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box",
                              WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                  {r.manual_guidance}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <div className="empty" style={{ padding: 16, color: "var(--green)" }}>
          All clear — nothing waiting for manual review.
        </div>
      )}
    </div>
  );
}

function ActiveScanCard({ scan }) {
  const [logs, setLogs] = useState([]);
  const logRef = useRef(null);

  useEffect(() => {
    if (!scan?.scan_id) return;
    const poll = createPoller(
      () => api.getScanLogs(scan.scan_id),
      (l) => {
        setLogs((l || []).slice(-40));
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
      },
      2000,
    );
    return () => poll.stop();
  }, [scan?.scan_id]);

  if (!scan || !scan.scan_id) return null;

  const phases = ["RECON", "OSINT", "SCAN", "EXPLOIT", "POST"];
  const currentPhase = (scan.phase || "RECON").toUpperCase();

  return (
    <div className="card active-scan" style={{ marginBottom: 20, position: "relative" }}>
      <div className="flex-between" style={{ marginBottom: 12 }}>
        <div>
          <h3 style={{ marginBottom: 2, display: "flex", alignItems: "center", gap: 8 }}>
            <span className="badge running">LIVE</span>
            Active Scan
          </h3>
          <span style={{ fontSize: 14, color: "var(--text-h)", fontWeight: 600 }}>{scan.target}</span>
        </div>
        <span style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>{scan.scan_id}</span>
      </div>

      <div className="phase-steps">
        {phases.map(p => {
          const idx = phases.indexOf(p);
          const curIdx = phases.indexOf(currentPhase);
          const cls = idx < curIdx ? "completed" : idx === curIdx ? "active" : "";
          return (
            <div key={p} className={`phase-step ${cls}`}>
              <span className="phase-dot" />
              {p}
            </div>
          );
        })}
      </div>

      {logs.length > 0 && (
        <div className="log-terminal" ref={logRef}>
          {logs.map((l, i) => (
            <div key={i} className={`log-line ${classifyLog(l)}`}>
              {typeof l === "string" ? l : l.message || JSON.stringify(l)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function classifyLog(l) {
  const msg = typeof l === "string" ? l : l.message || "";
  const low = msg.toLowerCase();
  if (low.includes("error") || low.includes("fail")) return "error";
  if (low.includes("warn")) return "warning";
  if (low.includes("found") || low.includes("confirmed") || low.includes("success")) return "success";
  return "info";
}

function SeverityDonut({ stats }) {
  const data = [
    { label: "Critical", value: stats.critical_count || 0, color: "#e7000b" },
    { label: "High", value: stats.high_count || 0, color: "#ea580c" },
    { label: "Medium", value: stats.medium_count || 0, color: "#ca8a04" },
    { label: "Low", value: stats.low_count || 0, color: "#2563eb" },
    { label: "Info", value: stats.info_count || 0, color: "#7c3aed" },
  ];
  const total = data.reduce((s, d) => s + d.value, 0);
  if (total === 0) return <div className="empty" style={{ padding: 20 }}>No findings yet</div>;

  const r = 70, cx = 100, cy = 100, stroke = 16;
  let offset = 0;
  const circ = 2 * Math.PI * r;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 28, padding: "8px 0" }}>
      <svg width="200" height="200" viewBox="0 0 200 200">
        {data.map((d, i) => {
          if (d.value === 0) return null;
          const pct = d.value / total;
          const dash = circ * pct;
          const gap = circ - dash;
          const el = (
            <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={d.color}
              strokeWidth={stroke} strokeDasharray={`${dash} ${gap}`}
              strokeDashoffset={-offset} transform={`rotate(-90 ${cx} ${cy})`}
              style={{ opacity: 0.85 }} />
          );
          offset += dash;
          return el;
        })}
        <text x={cx} y={cy - 6} textAnchor="middle" fill="#f7f9fa" fontSize="28" fontWeight="300" fontFamily="var(--sans)">{total}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="#828384" fontSize="10" fontWeight="500" letterSpacing="1.8px">FINDINGS</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {data.map(d => (
          <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
            <span style={{ width: 10, height: 10, borderRadius: 3, background: d.color, flexShrink: 0 }} />
            <span style={{ color: "var(--text)", minWidth: 60 }}>{d.label}</span>
            <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function QuickStats({ stats }) {
  const items = [
    { label: "Confirmed", value: stats.confirmed_count || 0, total: stats.total_vulns || 1, color: "var(--green)" },
    { label: "Rejected", value: stats.rejected_count || 0, total: stats.total_vulns || 1, color: "var(--red)" },
    { label: "Avg Duration", value: stats.avg_duration ? fmtDur(stats.avg_duration) : "-", type: "text" },
    { label: "Last Scan", value: stats.last_scan ? fmtDate(stats.last_scan) : "-", type: "text" },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14, padding: "4px 0" }}>
      {items.map(it => (
        <div key={it.label}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
            <span style={{ color: "var(--text-dim)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px", fontSize: 11 }}>{it.label}</span>
            {it.type === "text" ? (
              <span style={{ color: "var(--text-h)", fontFamily: "var(--mono)", fontSize: 12 }}>{it.value}</span>
            ) : (
              <span style={{ color: it.color, fontFamily: "var(--mono)", fontWeight: 700 }}>{it.value}</span>
            )}
          </div>
          {it.type !== "text" && (
            <div className="progress-bar-bg">
              <div className="progress-bar-fill" style={{ width: `${Math.min((it.value / it.total) * 100, 100)}%`, background: it.color }} />
            </div>
          )}
        </div>
      ))}
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
