import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [newTarget, setNewTarget] = useState("");
  const [loading, setLoading] = useState(true);
  const [scanModal, setScanModal] = useState(null);
  const navigate = useNavigate();

  const load = () => {
    api.getTargets()
      .then(setTargets)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const addTarget = () => {
    const t = newTarget.trim();
    if (!t) return;
    api.addTarget({ url: t }).then(() => {
      setNewTarget("");
      load();
    }).catch(() => {});
  };

  const deleteTarget = (id) => {
    api.deleteTarget(id).then(load).catch(() => {});
  };

  if (loading) return <div className="loading">Loading targets</div>;

  return (
    <div>
      <div className="page-header">
        <h1>Targets</h1>
      </div>

      <div className="card">
        <h3>Add Target</h3>
        <div className="form-row">
          <div className="form-group" style={{ flex: 1 }}>
            <label>Domain / URL</label>
            <input
              type="text"
              placeholder="https://example.com"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addTarget()}
              style={{ minWidth: 320 }}
            />
          </div>
          <button className="btn btn-primary" onClick={addTarget}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
            Add Target
          </button>
        </div>
      </div>

      {targets.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">&#9678;</div>
          No targets configured. Add a target above to begin.
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Added</th>
                <th>Last Scan</th>
                <th>Scans</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t, i) => (
                <tr key={i}>
                  <td style={{ color: "var(--text-h)", fontWeight: 600 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: "var(--accent)", opacity: 0.6 }}>
                        <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
                      </svg>
                      {t.url || t.target || t}
                    </div>
                  </td>
                  <td style={{ fontSize: 12, color: "var(--text-dim)" }}>{t.added ? fmtDate(t.added) : "-"}</td>
                  <td style={{ fontSize: 12 }}>{t.last_scan ? fmtDate(t.last_scan) : <span style={{ color: "var(--text-dim)" }}>Never</span>}</td>
                  <td style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{t.scan_count || 0}</td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                      <button className="btn btn-sm btn-primary" onClick={() => setScanModal({ target: t.url || t.target || t })}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12h14M12 5l7 7-7 7" /></svg>
                        Scan
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={() => deleteTarget(t.id)}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" /></svg>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {scanModal && (
        <ScanModal
          target={scanModal.target}
          onClose={() => setScanModal(null)}
          onStarted={() => { setScanModal(null); load(); navigate("/live"); }}
        />
      )}
    </div>
  );
}

function ScanModal({ target, onClose, onStarted }) {
  const [tier, setTier] = useState("DEEP");
  const [autoApprove, setAutoApprove] = useState(true);
  const [skipOsint, setSkipOsint] = useState(false);
  const [resetDedup, setResetDedup] = useState(false);
  const [selectedPhases, setSelectedPhases] = useState(["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"]);
  const [showCreds, setShowCreds] = useState(false);
  const [credList, setCredList] = useState([{ role: "admin", username: "", password: "", login_url: "" }]);
  const [state, setState] = useState("config"); // config | launching | running | stopped | completed | failed
  const [scanId, setScanId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");
  const logRef = useRef(null);

  const tiers = [
    { id: "POC", name: "POC", desc: "Quick recon only" },
    { id: "SHALLOW", name: "Shallow", desc: "Recon + basic scan" },
    { id: "DEEP", name: "Deep", desc: "Full autonomous pentest" },
  ];

  const phaseOptions = [
    { id: "RECON", name: "Recon", desc: "Subdomain enum, port scan, tech fingerprint" },
    { id: "ACTIVE_SCANNING", name: "Vuln Assessment", desc: "Nuclei scans, injection testing" },
    { id: "EXPLOITATION", name: "Exploitation", desc: "Exploit execution, post-exploit" },
    { id: "REPORTING", name: "Reporting", desc: "Retest, validate, generate report" },
  ];

  const togglePhase = (id) => {
    setSelectedPhases(prev =>
      prev.includes(id) ? prev.filter(p => p !== id) : [...prev, id]
    );
  };

  const applyPreset = (preset) => {
    if (preset === "recon") setSelectedPhases(["RECON"]);
    else if (preset === "recon+scan") setSelectedPhases(["RECON", "ACTIVE_SCANNING"]);
    else if (preset === "no-exploit") setSelectedPhases(["RECON", "ACTIVE_SCANNING", "REPORTING"]);
    else setSelectedPhases(["RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"]);
  };

  const startScan = async () => {
    setState("launching");
    setError("");
    try {
      const validCreds = credList.filter(c => c.username && c.password);
      const data = await api.startScan({
        target,
        tier,
        auto_approve: autoApprove,
        skip_osint: skipOsint,
        reset_dedup: resetDedup,
        phases: selectedPhases,
        credentials: validCreds,
      });
      setScanId(data.scan_id || data.job_id);
      setState("running");
      setTimeout(() => onStarted(data.scan_id || data.job_id), 600);
    } catch (err) {
      setError(err.message || "Failed to start scan");
      setState("failed");
    }
  };

  const stopScan = async () => {
    if (!scanId) return;
    try {
      await api.stopScan(scanId);
      setState("stopped");
    } catch { }
  };

  const resumeScan = async () => {
    if (!scanId) return;
    try {
      await api.resumeScan(scanId);
      setState("running");
    } catch { }
  };

  useEffect(() => {
    if (state !== "running" || !scanId) return;
    const iv = setInterval(() => {
      api.getScanLogs(scanId).then(l => {
        setLogs(l.slice(-50));
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
      }).catch(() => {});
      api.getScanStatus(scanId).then(s => {
        if (s?.status === "completed") setState("completed");
        if (s?.status === "failed") setState("failed");
        if (s?.status === "stopped") setState("stopped");
      }).catch(() => {});
    }, 2000);
    return () => clearInterval(iv);
  }, [state, scanId]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="flex-between" style={{ marginBottom: 20 }}>
          <h2 style={{ margin: 0, display: "flex", alignItems: "center", gap: 10 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2"><circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" /></svg>
            {state === "config" ? "Configure Scan" : "Scan Progress"}
          </h2>
          <button className="btn btn-sm btn-ghost" onClick={onClose} style={{ fontSize: 18 }}>&times;</button>
        </div>

        <div style={{ fontSize: 14, color: "var(--text-h)", fontWeight: 600, marginBottom: 16, fontFamily: "var(--mono)" }}>{target}</div>

        {state === "config" && (
          <>
            <h3>Scan Depth</h3>
            <div className="tier-selector">
              {tiers.map(t => (
                <div key={t.id} className={`tier-card ${tier === t.id ? "selected" : ""}`} onClick={() => setTier(t.id)}>
                  <div className="tier-name">{t.name}</div>
                  <div className="tier-desc">{t.desc}</div>
                </div>
              ))}
            </div>

            <h3 style={{ marginTop: 20 }}>Execution Phases</h3>
            <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
              <button className="btn btn-sm" onClick={() => applyPreset("recon")} style={{ fontSize: 11 }}>Recon Only</button>
              <button className="btn btn-sm" onClick={() => applyPreset("recon+scan")} style={{ fontSize: 11 }}>Recon + Scan</button>
              <button className="btn btn-sm" onClick={() => applyPreset("no-exploit")} style={{ fontSize: 11 }}>No Exploit</button>
              <button className="btn btn-sm" onClick={() => applyPreset("all")} style={{ fontSize: 11 }}>Full Test</button>
            </div>
            <div className="scan-options">
              {phaseOptions.map(p => (
                <label key={p.id} className={`scan-option ${selectedPhases.includes(p.id) ? "selected" : ""}`}>
                  <input type="checkbox" checked={selectedPhases.includes(p.id)} onChange={() => togglePhase(p.id)} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</div>
                    <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>{p.desc}</div>
                  </div>
                </label>
              ))}
            </div>

            <h3 style={{ marginTop: 20 }}>Options</h3>
            <div className="scan-options">
              <label className={`scan-option ${autoApprove ? "selected" : ""}`}>
                <input type="checkbox" checked={autoApprove} onChange={(e) => setAutoApprove(e.target.checked)} />
                Auto-approve exploits
              </label>
              <label className={`scan-option ${skipOsint ? "selected" : ""}`}>
                <input type="checkbox" checked={skipOsint} onChange={(e) => setSkipOsint(e.target.checked)} />
                Skip OSINT phase
              </label>
              <label className={`scan-option ${resetDedup ? "selected" : ""}`}>
                <input type="checkbox" checked={resetDedup} onChange={(e) => setResetDedup(e.target.checked)} />
                Reset deduplication
              </label>
            </div>

            <h3 style={{ marginTop: 20, cursor: "pointer" }} onClick={() => setShowCreds(!showCreds)}>
              Login Credentials {showCreds ? "▾" : "▸"} <span style={{ fontSize: 11, color: "var(--text-dim)", fontWeight: 400 }}>(optional — enables authenticated testing)</span>
            </h3>
            {showCreds && (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {credList.map((cred, i) => (
                  <div key={i} style={{ display: "flex", flexDirection: "column", gap: 6, padding: 10, borderRadius: 8, border: "1px solid var(--border)", background: "rgba(247,249,250,0.03)" }}>
                    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                      <span style={{ fontSize: 11, color: "var(--text-dim)", minWidth: 30 }}>Role</span>
                      <select value={cred.role} onChange={(e) => { const c = [...credList]; c[i] = { ...c[i], role: e.target.value }; setCredList(c); }}
                        style={{ flex: 1, padding: "6px 8px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-card)", color: "var(--text)", fontSize: 12 }}>
                        <option value="admin">Admin</option>
                        <option value="customer">Customer</option>
                        <option value="sales">Sales</option>
                        <option value="manager">Manager</option>
                        <option value="user">Regular User</option>
                        <option value="api">API / Service</option>
                        <option value="other">Other</option>
                      </select>
                      {credList.length > 1 && (
                        <button className="btn btn-sm btn-danger" onClick={() => setCredList(credList.filter((_, j) => j !== i))} style={{ padding: "4px 8px", fontSize: 11 }}>✕</button>
                      )}
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input type="text" placeholder="Username / email" value={cred.username} onChange={(e) => { const c = [...credList]; c[i] = { ...c[i], username: e.target.value }; setCredList(c); }}
                        style={{ flex: 1, padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-card)", color: "var(--text)", fontSize: 12 }} />
                      <input type="password" placeholder="Password" value={cred.password} onChange={(e) => { const c = [...credList]; c[i] = { ...c[i], password: e.target.value }; setCredList(c); }}
                        style={{ flex: 1, padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-card)", color: "var(--text)", fontSize: 12 }} />
                    </div>
                    <input type="url" placeholder="Login URL (e.g. https://example.com/admin/login)" value={cred.login_url} onChange={(e) => { const c = [...credList]; c[i] = { ...c[i], login_url: e.target.value }; setCredList(c); }}
                      style={{ padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)", background: "var(--bg-card)", color: "var(--text)", fontSize: 12 }} />
                  </div>
                ))}
                <button className="btn btn-sm" onClick={() => setCredList([...credList, { role: "user", username: "", password: "", login_url: "" }])}
                  style={{ alignSelf: "flex-start", fontSize: 11, padding: "4px 12px" }}>+ Add another role</button>
              </div>
            )}

            {error && <div className="error-msg">{error}</div>}

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 20 }}>
              <button className="btn" onClick={onClose}>Cancel</button>
              <button className="btn btn-primary" onClick={startScan}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polygon points="5 3 19 12 5 21 5 3" /></svg>
                Launch Scan
              </button>
            </div>
          </>
        )}

        {state === "launching" && (
          <div className="empty">
            <div className="loading" style={{ padding: 20 }}>Initializing scan engine</div>
          </div>
        )}

        {(state === "running" || state === "stopped" || state === "completed" || state === "failed") && (
          <>
            <div className="flex-between" style={{ marginBottom: 12 }}>
              <span className={`badge ${state === "running" ? "running" : state === "completed" ? "confirmed" : state === "stopped" ? "medium" : "critical"}`}>
                {state.toUpperCase()}
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                {state === "running" && (
                  <button className="btn btn-sm btn-danger" onClick={stopScan}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><rect x="6" y="6" width="12" height="12" /></svg>
                    Stop
                  </button>
                )}
                {state === "stopped" && (
                  <button className="btn btn-sm btn-primary" onClick={resumeScan}>Resume</button>
                )}
                {(state === "completed" || state === "failed") && (
                  <button className="btn btn-sm" onClick={onStarted}>View Results</button>
                )}
              </div>
            </div>

            {logs.length > 0 && (
              <div className="log-terminal" ref={logRef} style={{ maxHeight: 300 }}>
                {logs.map((l, i) => {
                  const msg = typeof l === "string" ? l : l.message || JSON.stringify(l);
                  return <div key={i} className={`log-line ${classifyLog(msg)}`}>{msg}</div>;
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function classifyLog(msg) {
  const low = (typeof msg === "string" ? msg : "").toLowerCase();
  if (low.includes("error") || low.includes("fail")) return "error";
  if (low.includes("warn")) return "warning";
  if (low.includes("found") || low.includes("confirmed") || low.includes("success")) return "success";
  return "info";
}

function fmtDate(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}
