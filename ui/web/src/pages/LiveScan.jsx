import React, { useEffect, useState, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { api, createScanSocket, createPoller } from "../api";
import ActivityLog from "../components/ActivityLog";
import ReconPanel from "../components/ReconPanel";
import { OsintSection } from "../components/ReconPanel";
import AccessGainedPanel from "../components/AccessGainedPanel";
import LiveAgentsPanel from "../components/LiveAgentsPanel";
import BlackboardPanel from "../components/BlackboardPanel";
import AttackGraphPanel from "../components/AttackGraphPanel";
import LlmCallsPanel from "../components/LlmCallsPanel";
import JevDecisionsPanel from "../components/JevDecisionsPanel";
import HumanAssistPanel from "../components/HumanAssistPanel";
import ScanChatPanel from "../components/ScanChatPanel";
import ArtifactsPanel from "../components/ArtifactsPanel";
import CostRiskPanel from "../components/CostRiskPanel";
import CoveragePanel from "../components/CoveragePanel";
import AttackChainsPanel from "../components/AttackChainsPanel";
import SastPanel from "../components/SastPanel";
import { methodColor, fmtDate, parseTs, asText } from "../components/utils";

const PHASES = ["BUSINESS_UNDERSTANDING", "RECON", "ACTIVE_SCANNING", "EXPLOITATION", "REPORTING"];
const PHASE_LABELS = { BUSINESS_UNDERSTANDING: "Business Understanding", RECON: "Recon", ACTIVE_SCANNING: "Vulnerability Assessment", EXPLOITATION: "Exploitation", REPORTING: "Reporting" };

export default function LiveScan() {
  const [jobs, setJobs] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [recentScans, setRecentScans] = useState([]);
  const navigate = useNavigate();

  const autoSelected = useRef(false);

  // Fallback so the page is never blank when nothing is actively running:
  // show the most recent scans (click to open their detail).
  useEffect(() => {
    api.getScans()
      .then((list) => setRecentScans(Array.isArray(list) ? list.slice(0, 12) : []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    const p = createPoller(
      () => api.getActiveScans(),
      (j) => {
        const active = Array.isArray(j) ? j.filter(s => !["completed", "failed", "cancelled"].includes(s.status)) : [];
        setJobs(active);
        if (!autoSelected.current && active.length > 0) {
          const live = active.find(s => s.status === "running" || s.status === "starting");
          setSelected((live || active[0]).job_id);
          autoSelected.current = true;
        }
        setLoading(false);
      },
      4000,
    );
    return () => p.stop();
  }, []);

  if (loading) return <div className="loading">Loading active scans</div>;

  const activeStatuses = new Set(["running", "starting", "stopping", "stopped"]);
  const running = jobs.filter(j => activeStatuses.has(j.status));
  const recent = jobs.filter(j => !activeStatuses.has(j.status));

  return (
    <div>
      <div className="page-header">
        <h1>Live Scans</h1>
        <button className="btn btn-primary" onClick={() => navigate("/targets")}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
          New Scan
        </button>
      </div>

      {jobs.length === 0 ? (
        recentScans.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">&#9881;</div>
            No active or recent scans. Start a scan from the Targets page.
          </div>
        ) : (
          <div>
            <div className="empty" style={{ padding: 16, marginBottom: 12 }}>
              No scan is running right now. Recent scans below — click to open, or start a new one.
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Target</th><th>Status</th><th>Started</th><th>Scan ID</th></tr></thead>
                <tbody>
                  {recentScans.map((s) => {
                    const id = s.scan_id || s.job_id;
                    return (
                      <tr key={id} style={{ cursor: "pointer" }} onClick={() => navigate(`/scans/${id}`)}>
                        <td style={{ color: "var(--text-h)" }}>{s.target}</td>
                        <td><span className={`badge ${(s.status || "").toLowerCase()}`}>{(s.status || "").toUpperCase()}</span></td>
                        <td style={{ fontSize: 12, color: "var(--text-dim)" }}>{s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</td>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{id}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )
      ) : (
        <>
          {running.length > 0 && (
            <div className="card-grid" style={{ marginBottom: 16 }}>
              {running.map(j => (
                <div key={j.job_id} className={`stat-card accent-accent ${selected === j.job_id ? "" : ""}`}
                  style={{ cursor: "pointer", border: selected === j.job_id ? "1px solid var(--accent)" : undefined }}
                  onClick={() => setSelected(j.job_id)}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className={`badge ${j.status === "running" || j.status === "starting" ? "running" : "medium"}`}>
                      {j.status === "running" || j.status === "starting" ? "LIVE" : j.status?.toUpperCase()}
                    </span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: "var(--text-h)" }}>{j.target}</span>
                  </div>
                  <span className="sub" style={{ fontFamily: "var(--mono)" }}>{j.job_id}</span>
                </div>
              ))}
            </div>
          )}

          {recent.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <h3>Recent Jobs</h3>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Job ID</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Started</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map(j => (
                      <tr key={j.job_id}>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{j.job_id}</td>
                        <td style={{ color: "var(--text-h)", fontWeight: 600 }}>{j.target}</td>
                        <td>
                          <span className={`badge ${j.status === "completed" ? "confirmed" : j.status === "failed" ? "critical" : "medium"}`}>
                            {j.status}
                          </span>
                        </td>
                        <td style={{ fontSize: 12 }}>{fmtDate(j.started_at)}</td>
                        <td>
                          <button className="btn btn-sm" onClick={() => setSelected(j.job_id)}>View</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {selected && <LiveScanDetail key={selected} jobId={selected} />}
        </>
      )}
    </div>
  );
}


function LiveScanDetail({ jobId }) {
  const [job, setJob] = useState(null);
  const [progress, setProgress] = useState({});
  const [results, setResults] = useState(null);
  const [logs, setLogs] = useState({ lines: [], total: 0 });
  const [understanding, setUnderstanding] = useState(null);
  const [tab, setTab] = useState("overview");
  const logRef = useRef(null);

  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    setTab("overview");

    // WebSocket for real-time updates. When WS is connected we stop the REST
    // fallback poll to avoid the WS-vs-REST race that could overwrite fresh WS
    // payloads with stale REST responses (#087).
    const sock = createScanSocket(jobId, (msg) => {
      if (msg.type === "live_update") {
        setWsConnected(true);
        if (msg.status) setJob(prev => prev ? { ...prev, status: msg.status } : prev);
        if (msg.progress && Object.keys(msg.progress).length) setProgress(msg.progress);
        if (msg.results && Object.keys(msg.results).length) setResults(msg.results);
        if (msg.log_tail && msg.log_tail.length) {
          setLogs(prev => {
            const combined = [...(prev.lines || [])];
            for (const line of msg.log_tail) {
              if (!combined.includes(line)) combined.push(line);
            }
            const trimmed = combined.length > 500 ? combined.slice(-500) : combined;
            return { lines: trimmed, total: trimmed.length };
          });
        }
      }
    });

    // REST fallback via createPoller. AbortController + generation counter
    // prevent an older slow response from overwriting newer WS state.
    const poller = createPoller(
      () => Promise.all([
        api.getScanJob(jobId).catch(() => null),
        api.getLiveProgress(jobId).catch(() => ({})),
        api.getLiveResults(jobId).catch(() => null),
        api.getScanLogs(jobId, 300).catch(() => ({ lines: [], total: 0 })),
        api.getUnderstanding(jobId).catch(() => null),
      ]),
      ([j, p, r, l, u]) => {
        if (j) setJob(j);
        if (p && Object.keys(p).length) setProgress(p);
        if (r) setResults(r);
        if (l) setLogs(l);
        if (u && Object.keys(u).length) setUnderstanding(u);
      },
      10000,
    );

    return () => {
      sock.close();
      poller.stop();
    };
  }, [jobId]);

  useEffect(() => {
    // Only auto-scroll when LogsSection's pinBottom state is true.
    // We check if user is near bottom by inspecting the element directly.
    if (logRef.current && tab === "logs") {
      const el = logRef.current;
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
      if (atBottom) {
        el.scrollTop = el.scrollHeight;
      }
    }
  }, [logs, tab]);

  if (!job) return <div className="loading">Loading scan details</div>;

  const isRunning = job.status === "running" || job.status === "starting";
  const isStopping = job.status === "stopping";
  const isStopped = job.status === "stopped";
  const currentPhase = progress?.phase || "BUSINESS_UNDERSTANDING";

  const stopScan = () => api.stopScan(jobId).catch(() => {});
  const resumeScan = () => api.resumeScan({ target: job.target, tier: job.tier || "POC" }).catch(() => {});
  const cancelScan = () => {
    if (confirm("Cancel this scan? This cannot be undone.")) {
      api.cancelScan(jobId).then(() => window.location.reload()).catch(() => {});
    }
  };

  const recon = results?.recon || { subdomains: [], endpoints: [], technologies: {}, ports: [], ips: [], dns_records: [], tool_results: {}, tool_executions: [] };
  const vulns = results?.vulnerabilities || [];
  const exploits = results?.exploits || [];
  const requests = results?.captured_requests || [];

  const tabs = [
    { id: "chat", label: "Ask (LLM)" },
    { id: "overview", label: "Overview" },
    { id: "understanding", label: "Understanding" },
    { id: "recon", label: `Recon (${recon.subdomains.length + recon.endpoints.length})` },
    { id: "osint", label: `OSINT (${recon.osint?.summary?.employees || 0}+${recon.osint?.summary?.leaked_credentials || 0})` },
    { id: "vulns", label: `Vulnerabilities (${vulns.length})` },
    { id: "access", label: "Access Gained" },
    { id: "exploits", label: `Exploits (${exploits.length})` },
    { id: "chains", label: "Attack Chains" },
    { id: "coverage", label: "Coverage" },
    { id: "sast", label: "SAST" },
    { id: "artifacts", label: "Artifacts / PoC" },
    { id: "agents", label: "Parallel Agents" },
    { id: "blackboard", label: "Blackboard" },
    { id: "attackgraph", label: "Attack Graph" },
    { id: "llmio", label: "LLM I/O" },
    { id: "cost-risk", label: "Cost & Models" },
    { id: "jev", label: "Jev Decisions" },
    { id: "human", label: "Human Assist" },
    { id: "requests", label: `Requests (${requests.length})` },
    { id: "logs", label: `Logs (${logs.total})` },
  ];

  return (
    <div className={`card ${isRunning ? "scan-running" : ""}`} style={{ marginTop: 16, position: "relative" }}>
      <div className="flex-between" style={{ marginBottom: 12 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <span className={`badge ${isRunning ? "running" : isStopping ? "medium" : job.status === "completed" ? "confirmed" : isStopped ? "medium" : "critical"}`}>
              {isRunning && <span className="live-dot" />}{job.status?.toUpperCase()}
            </span>
            <span style={{ fontSize: 16, fontWeight: 700, color: "var(--text-h)" }}>{job.target}</span>
            {isRunning && <LiveElapsed startedAt={job.started_at} />}
          </div>
          <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-dim)" }}>
            Job: {jobId} | Started: {fmtDate(job.started_at)} {job.finished_at ? `| Finished: ${fmtDate(job.finished_at)}` : ""}
            {isRunning && (
              <span style={{ marginLeft: 8, color: wsConnected ? "var(--green, #22c55e)" : "var(--text-dim)" }}>
                {wsConnected ? "● Live" : "○ Polling"}
              </span>
            )}
          </span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {(isRunning || isStopping) && (
            <button className="btn btn-sm btn-danger" onClick={stopScan} disabled={isStopping}>
              {isStopping ? "Stopping..." : "Stop"}
            </button>
          )}
          {isStopped && (
            <>
              <button className="btn btn-sm btn-primary" onClick={resumeScan}>Resume</button>
              <button className="btn btn-sm btn-danger" onClick={cancelScan}>Cancel</button>
            </>
          )}
        </div>
      </div>

      <PhaseProgress currentPhase={currentPhase} status={progress?.status} isRunning={isRunning} phases={job.phases} />

      <div style={{ display: "flex", gap: 12, margin: "16px 0 4px", flexWrap: "wrap" }}>
        <MiniStat label="Subdomains" value={recon.subdomains.length} color="var(--cyan)" />
        <MiniStat label="Endpoints" value={recon.endpoints.length} color="var(--blue)" />
        <MiniStat label="Vulns" value={vulns.length} color="var(--orange)" />
        <MiniStat label="Exploits" value={exploits.length} color="var(--red)" />
        <MiniStat label="Requests" value={requests.length} color="var(--purple)" />
      </div>

      {isRunning && <HealthIndicator />}

      <div className="tabs" style={{ marginTop: 16 }}>
        {tabs.map(t => (
          <button key={t.id} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "chat" && <ScanChatPanel scanId={jobId} />}
      {tab === "overview" && <OverviewSection recon={recon} vulns={vulns} exploits={exploits} progress={progress} />}
      {tab === "understanding" && <UnderstandingSection data={understanding} />}
      {tab === "recon" && <ReconPanel context={recon} scanId={jobId} />}
      {tab === "osint" && <OsintSection osint={recon.osint || {}} />}
      {tab === "vulns" && <VulnsSection vulns={vulns} />}
      {tab === "access" && <AccessGainedPanel scanId={jobId} poll />}
      {tab === "exploits" && <ExploitsSection exploits={exploits} />}
      {tab === "chains" && <AttackChainsPanel scanId={jobId} />}
      {tab === "coverage" && <CoveragePanel scanId={jobId} />}
      {tab === "sast" && <SastPanel scanId={jobId} />}
      {tab === "cost-risk" && <CostRiskPanel scanId={jobId} />}
      {tab === "activity" && <ActivityLog scanId={jobId} poll />}
      {tab === "agents" && <LiveAgentsPanel scanId={jobId} poll />}
      {tab === "blackboard" && <BlackboardPanel scanId={jobId} poll={isRunning} />}
      {tab === "attackgraph" && <AttackGraphPanel scanId={jobId} poll={isRunning} />}
      {tab === "llmio" && <LlmCallsPanel scanId={jobId} poll={isRunning} />}
      {tab === "jev" && <JevDecisionsPanel scanId={jobId} poll={isRunning} />}
      {tab === "human" && <HumanAssistPanel scanId={jobId} poll={isRunning} />}
      {tab === "artifacts" && <ArtifactsPanel scanId={jobId} poll />}
      {tab === "requests" && <RequestsSection requests={requests} jobId={jobId} />}
      {tab === "logs" && <LogsSection logRef={logRef} jobId={jobId} />}
    </div>
  );
}


function PhaseProgress({ currentPhase, status, isRunning, phases }) {
  const activePhases = phases || PHASES;
  return (
    <div className="phase-steps">
      {PHASES.map(p => {
        const idx = PHASES.indexOf(p);
        const curIdx = PHASES.indexOf(currentPhase);
        const included = activePhases.includes(p);
        let cls = "";
        if (!included) cls = "";
        else if (status === "completed") cls = "completed";
        else if (idx < curIdx) cls = "completed";
        else if (idx === curIdx && isRunning) cls = "active";
        else if (idx === curIdx && !isRunning) cls = "completed";
        return (
          <div key={p} className={`phase-step ${cls}`} style={{ opacity: included ? 1 : 0.3 }}>
            <span className="phase-dot" />
            {PHASE_LABELS[p]}
          </div>
        );
      })}
    </div>
  );
}


function MiniStat({ label, value, color }) {
  const prev = useRef(value);
  const [flash, setFlash] = useState(false);
  useEffect(() => {
    if (prev.current !== value) {
      prev.current = value;
      setFlash(true);
      const t = setTimeout(() => setFlash(false), 700);
      return () => clearTimeout(t);
    }
  }, [value]);
  return (
    <div className={flash ? "stat-flash" : ""} style={{
      padding: "8px 14px", background: "var(--bg-surface)", border: "1px solid var(--border)",
      borderRadius: "var(--radius-sm)", display: "flex", alignItems: "center", gap: 8, fontSize: 12,
      transition: "background 0.3s ease",
    }}>
      <span style={{ color: "var(--text-dim)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px", fontSize: 10 }}>{label}</span>
      <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color, fontSize: 14 }}>{value}</span>
    </div>
  );
}


// Live-ticking elapsed clock for a running scan.
function LiveElapsed({ startedAt }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const start = startedAt ? parseTs(startedAt) : now;
  const secs = Number.isFinite(start) ? Math.max(0, Math.floor((now - start) / 1000)) : 0;
  const hh = String(Math.floor(secs / 3600)).padStart(2, "0");
  const mm = String(Math.floor((secs % 3600) / 60)).padStart(2, "0");
  const ss = String(secs % 60).padStart(2, "0");
  return <span style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, color: "var(--accent)" }}>{hh}:{mm}:{ss}</span>;
}


// Always-visible streaming activity feed while the scan runs — the biggest
// "this is alive" signal. Shows the tail of the log stream, auto-scrolling.
function UChip({ children }) {
  return <span style={{ display: "inline-block", padding: "3px 9px", borderRadius: 6, fontSize: 12,
    fontFamily: "var(--mono)", background: "var(--accent-dim, rgba(0,113,227,0.10))",
    color: "var(--text-h)", border: "1px solid var(--border)" }}>{children}</span>;
}

function UnderstandingSection({ data }) {
  if (!data || !data.domain) {
    return <div style={{ color: "var(--text-dim)", fontSize: 13, padding: 12 }}>
      Business Understanding runs as the first phase — the report appears here once it completes.
    </div>;
  }
  const req = data.required_testing || [];
  const sens = data.data_sensitivity || {};
  const rules = data.business_rules || [];
  const inv = data.security_invariants || [];
  const skipped = data.skipped_families || [];
  const conf = Math.round((data.domain_confidence || 0) * 100);
  const invText = (x) => typeof x === "string" ? x : (x.rule || x.description || x.invariant || JSON.stringify(x));
  return (
    <div>
      <div className="card" style={{ margin: "0 0 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <h3 style={{ margin: 0 }}>What the model understood</h3>
          <UChip>domain: {data.domain}</UChip>
          <UChip>confidence: {conf}%</UChip>
          <UChip>source: {data.source || "n/a"}</UChip>
        </div>
      </div>

      <div className="two-col" style={{ marginBottom: 16 }}>
        <div className="card" style={{ margin: 0 }}>
          <h3>Sensitive Assets</h3>
          {Object.keys(sens).length === 0
            ? <div style={{ color: "var(--text-dim)", fontSize: 13 }}>None inferred</div>
            : <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
                {Object.entries(sens).map(([f, c]) => <UChip key={f}>{f} → {c}</UChip>)}
              </div>}
        </div>
        <div className="card" style={{ margin: 0 }}>
          <h3>Security Invariants (must hold)</h3>
          {inv.length === 0
            ? <div style={{ color: "var(--text-dim)", fontSize: 13 }}>None inferred</div>
            : <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 13, color: "var(--text-h)" }}>
                {inv.slice(0, 12).map((x, i) => <li key={i}>{invText(x)}</li>)}
              </ul>}
        </div>
      </div>

      {rules.length > 0 && (
        <div className="card" style={{ margin: "0 0 16px" }}>
          <h3>Business Rules</h3>
          <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 13, color: "var(--text-h)" }}>
            {rules.slice(0, 15).map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}

      <div className="card" style={{ margin: "0 0 16px" }}>
        <h3>What is required — prioritized test plan</h3>
        {req.length === 0
          ? <div style={{ color: "var(--text-dim)", fontSize: 13 }}>No plan produced</div>
          : <table style={{ width: "100%", fontSize: 13, marginTop: 8, borderCollapse: "collapse" }}>
              <thead><tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
                <th style={{ padding: "4px 8px" }}>Test Family</th>
                <th style={{ padding: "4px 8px" }}>Priority</th>
                <th style={{ padding: "4px 8px" }}>Why</th>
              </tr></thead>
              <tbody>
                {req.map((it, i) => (
                  <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
                    <td style={{ padding: "5px 8px", fontFamily: "var(--mono)", color: "var(--text-h)" }}>{it.family}</td>
                    <td style={{ padding: "5px 8px", fontFamily: "var(--mono)" }}>{it.priority}</td>
                    <td style={{ padding: "5px 8px", color: "var(--text-dim)" }}>{it.why}</td>
                  </tr>
                ))}
              </tbody>
            </table>}
        {skipped.length > 0 && (
          <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-dim)", display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
            <span>Skipped (out of scope for this app):</span>
            {skipped.map(s => <UChip key={s}>{s}</UChip>)}
          </div>
        )}
      </div>
    </div>
  );
}

function OverviewSection({ recon, vulns, exploits, progress }) {
  const criticals = vulns.filter(v => (v.severity || "").toUpperCase() === "CRITICAL");
  const highs = vulns.filter(v => (v.severity || "").toUpperCase() === "HIGH");
  const confirmed = vulns.filter(v => (v.status || "").toUpperCase() === "CONFIRMED");

  return (
    <div>
      <div className="two-col" style={{ marginBottom: 16 }}>
        <div className="card" style={{ margin: 0 }}>
          <h3>Severity Breakdown</h3>
          {vulns.length === 0 ? <div style={{ color: "var(--text-dim)", fontSize: 13 }}>No findings yet</div> : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
              <SevBar label="Critical" count={criticals.length} total={vulns.length} color="var(--red)" />
              <SevBar label="High" count={highs.length} total={vulns.length} color="var(--orange)" />
              <SevBar label="Medium" count={vulns.filter(v => (v.severity || "").toUpperCase() === "MEDIUM").length} total={vulns.length} color="var(--yellow)" />
              <SevBar label="Low" count={vulns.filter(v => (v.severity || "").toUpperCase() === "LOW").length} total={vulns.length} color="var(--blue)" />
              <SevBar label="Info" count={vulns.filter(v => (v.severity || "").toUpperCase() === "INFO").length} total={vulns.length} color="var(--purple)" />
            </div>
          )}
        </div>
        <div className="card" style={{ margin: 0 }}>
          <h3>Recon Summary</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Subdomains</span>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>{recon.subdomains.length}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Endpoints</span>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>{recon.endpoints.length}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Technologies</span>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>
                {Object.values(recon.technologies).flat().length}
              </span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Open Ports</span>
              <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>{recon.ports.length}</span>
            </div>
            {(recon.directories?.length > 0 || recon.secrets?.length > 0 || recon.osint) && <>
              {recon.directories?.length > 0 && <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-dim)" }}>Directories</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>{recon.directories.length}</span>
              </div>}
              {recon.secrets?.length > 0 && <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-dim)" }}>Secrets</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--red)" }}>{recon.secrets.length}</span>
              </div>}
              {recon.osint?.summary?.employees > 0 && <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ color: "var(--text-dim)" }}>OSINT People</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--text-h)" }}>{recon.osint.summary.employees}</span>
              </div>}
            </>}
          </div>
        </div>
      </div>

      {confirmed.length > 0 && (
        <div className="card" style={{ margin: 0 }}>
          <h3>Confirmed Vulnerabilities ({confirmed.length})</h3>
          <div className="table-wrap" style={{ border: "none", boxShadow: "none" }}>
            <table>
              <thead><tr><th>Title</th><th>Severity</th><th>Type</th><th>Target</th></tr></thead>
              <tbody>
                {confirmed.slice(0, 10).map((v, i) => (
                  <tr key={i}>
                    <td style={{ color: "var(--text-h)", fontWeight: 500 }}>{v.title}</td>
                    <td><span className={`badge ${(v.severity || "info").toLowerCase()}`}>{v.severity}</span></td>
                    <td style={{ fontSize: 12 }}>{v.type || v.vuln_type || "-"}</td>
                    <td style={{ fontSize: 11, fontFamily: "var(--mono)" }}>{v.target || v.location || v.url || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}


function SevBar({ label, count, total, color }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12 }}>
      <span style={{ width: 55, fontWeight: 600, color: "var(--text-dim)" }}>{label}</span>
      <div className="progress-bar-bg" style={{ flex: 1 }}>
        <div className="progress-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ fontFamily: "var(--mono)", fontWeight: 700, width: 24, textAlign: "right", color: "var(--text-h)" }}>{count}</span>
    </div>
  );
}




function VulnsSection({ vulns }) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [expanded, setExpanded] = useState(null);

  let filtered = vulns.filter(v => {
    if (sevFilter !== "ALL" && (v.severity || "").toUpperCase() !== sevFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (v.title || "").toLowerCase().includes(q) ||
             (v.type || "").toLowerCase().includes(q) ||
             (v.target || v.location || v.url || "").toLowerCase().includes(q);
    }
    return true;
  });

  // Newest-first: findings arrive in discovery order, so the most recent is last;
  // reverse so the latest finding shows at the top during a live scan.
  filtered = filtered.slice().reverse();

  if (vulns.length === 0) return <div className="empty">No vulnerabilities discovered yet</div>;

  return (
    <div>
      <div className="filter-bar">
        <input type="text" placeholder="Search findings..." value={search} onChange={e => setSearch(e.target.value)} />
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          style={{ padding: "6px 10px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 12 }}>
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>
        <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{filtered.length} of {vulns.length}</span>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Title</th><th>Severity</th><th>Status</th><th>Type</th><th>Target</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            {filtered.map((v, i) => (
              <React.Fragment key={i}>
                <tr className="click-row" onClick={() => setExpanded(expanded === i ? null : i)}>
                  <td style={{ color: "var(--text-h)", fontWeight: 500, maxWidth: 300 }}>{v.title || "Untitled"}</td>
                  <td><span className={`badge ${(v.severity || "info").toLowerCase()}`}>{v.severity || "INFO"}</span></td>
                  <td><span className={`badge ${(v.status || "unconfirmed").toLowerCase()}`}>{v.status || "UNCONFIRMED"}</span></td>
                  <td style={{ fontSize: 12 }}>{v.type || v.vuln_type || "-"}</td>
                  <td style={{ fontSize: 11, fontFamily: "var(--mono)", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {v.target || v.location || v.url || "-"}
                  </td>
                  <td style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                    {v.confidence_score ? `${Math.round((typeof v.confidence_score === "number" && v.confidence_score <= 1 ? v.confidence_score * 100 : v.confidence_score))}%` : "-"}
                  </td>
                </tr>
                {expanded === i && (
                  <tr><td colSpan={6} style={{ padding: 0 }}>
                    <div style={{ padding: "14px 20px", background: "var(--bg)", borderTop: "1px solid var(--border)" }}>
                      <div className="vuln-detail-grid">
                        {(v.location || v.target || v.url) && <><span className="lbl">Location</span><span style={{ fontFamily: "var(--mono)", fontSize: 12, wordBreak: "break-all" }}>{v.location || v.target || v.url}</span></>}
                        {(v.parameter || v.param || v.injection_point) && <><span className="lbl">Parameter</span><span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{v.parameter || v.param || v.injection_point}</span></>}
                        {(v.lifecycle || v.status) && <><span className="lbl">State</span><span>{v.lifecycle || v.status}</span></>}
                        {v.impact_level && <><span className="lbl">Impact</span><span>{v.impact_level}</span></>}
                        {asText(v.details || v.description) && <><span className="lbl">Details</span><span style={{ whiteSpace: "pre-wrap" }}>{asText(v.details || v.description)}</span></>}
                        {asText(v.proof || v.evidence) && <><span className="lbl">Proof</span><span style={{ fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{asText(v.proof || v.evidence)}</span></>}
                        {(v.payload) && <><span className="lbl">Payload</span><span style={{ fontFamily: "var(--mono)", fontSize: 12, wordBreak: "break-all" }}>{asText(v.payload)}</span></>}
                        {asText(v.request) && <><span className="lbl">Request</span><pre style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 200, overflow: "auto" }}>{asText(v.request)}</pre></>}
                        {asText(v.response_snippet || v.response) && <><span className="lbl">Response</span><pre style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 200, overflow: "auto" }}>{asText(v.response_snippet || v.response)}</pre></>}
                        {asText(v.curl) && <><span className="lbl">cURL</span><pre style={{ margin: 0, fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{asText(v.curl)}</pre></>}
                        {asText(v.tool || v.source) && <><span className="lbl">Tool</span><span>{asText(v.tool || v.source)}</span></>}
                        {asText(v.remediation) && <><span className="lbl">Remediation</span><span style={{ whiteSpace: "pre-wrap" }}>{asText(v.remediation)}</span></>}
                        {v.cve_id && <><span className="lbl">CVE</span><span>{asText(v.cve_id)}</span></>}
                        {v.cwe_id && <><span className="lbl">CWE</span><span>{asText(v.cwe_id)}</span></>}
                      </div>
                      {!asText(v.details || v.description) && !asText(v.proof || v.evidence) && !asText(v.request) && (
                        <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 8 }}>
                          This finding recorded no detail/proof/request. Open it in Scan History after the scan for the full record.
                        </div>
                      )}
                    </div>
                  </td></tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ExploitsSection({ exploits }) {
  if (exploits.length === 0) return <div className="empty">No exploit results yet</div>;

  return (
    <div>
      {exploits.map((ex, i) => {
        const succeeded = ex.success || ex.exploited || ex.proof_found;
        const title = ex.name || ex.title || ex.vulnerability || ex.vuln_id
          || (ex.type ? `${ex.type} Exploit` : `Exploit #${i + 1}`);
        const target = ex.target || ex.url || ex.location || "-";
        const method = ex.method || ex.technique || ex.type || "-";
        const tool = ex.tool || ex.source || ex.source_agent || ex.agent || ex.sandbox
          || (ex.chain_id ? `Chain ${ex.chain_id}` : "-");
        const proof = ex.proof || ex.output || ex.result || ex.content || "";
        const error = ex.error || "";
        const payload = ex.payload || "";
        const details = ex.details || [];
        const step = ex.step ? `Step ${ex.step}` : "";

        return (
          <div key={i} className="card" style={{ margin: "0 0 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span className={`badge ${succeeded ? "critical" : error ? "medium" : "info"}`}>
                {succeeded ? "EXPLOITED" : error ? "FAILED" : "ATTEMPTED"}
              </span>
              <span style={{ fontWeight: 600, color: "var(--text-h)", fontSize: 14 }}>{title}</span>
              {step && <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{step}</span>}
            </div>
            <div className="vuln-detail-grid">
              <span className="lbl">Target</span>
              <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{target}</span>
              <span className="lbl">Method</span>
              <span>{method}</span>
              <span className="lbl">Tool / Agent</span>
              <span>{tool}</span>
              {ex.chain_id && <>
                <span className="lbl">Chain</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{ex.chain_id}</span>
              </>}
              {ex.severity && <>
                <span className="lbl">Severity</span>
                <span className={`badge ${ex.severity.toLowerCase()}`}>{ex.severity}</span>
              </>}
              {payload && <>
                <span className="lbl">Payload</span>
                <pre className="code-block" style={{ maxHeight: 120, margin: 0, whiteSpace: "pre-wrap" }}>{payload}</pre>
              </>}
              {proof && <>
                <span className="lbl">Proof</span>
                <pre className="code-block" style={{ maxHeight: 200, margin: 0, whiteSpace: "pre-wrap" }}>{typeof proof === "string" ? proof : JSON.stringify(proof, null, 2)}</pre>
              </>}
              {error && <>
                <span className="lbl">Error</span>
                <span style={{ color: "var(--red)", fontSize: 12 }}>{error}</span>
              </>}
              {details.length > 0 && <>
                <span className="lbl">Findings ({details.length})</span>
                <div style={{ fontSize: 12 }}>
                  {details.map((d, j) => (
                    <div key={j} style={{ padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
                      <span className={`badge ${(d.severity || "low").toLowerCase()}`} style={{ fontSize: 10, marginRight: 8 }}>
                        {d.severity || "INFO"}
                      </span>
                      <span style={{ fontWeight: 600 }}>{d.title || d.description || JSON.stringify(d)}</span>
                      {d.location && <span style={{ color: "var(--text-dim)", marginLeft: 8, fontFamily: "var(--mono)", fontSize: 11 }}>{d.location}</span>}
                    </div>
                  ))}
                </div>
              </>}
            </div>
          </div>
        );
      })}
    </div>
  );
}


function RequestsSection({ requests, jobId }) {
  const [expanded, setExpanded] = useState(null);
  const [exchanges, setExchanges] = useState(null);
  const [totalSent, setTotalSent] = useState(0);

  useEffect(() => {
    if (!jobId) { setExchanges([]); return; }
    let alive = true;
    const load = () => api.getHttpExchanges(jobId).then((r) => {
      if (!alive) return;
      setExchanges(Array.isArray(r.exchanges) ? r.exchanges : []);
      setTotalSent(r.total_sent || 0);
    }).catch(() => alive && setExchanges([]));
    load();
    const t = setInterval(load, 5000);  // refresh live during the scan
    return () => { alive = false; clearInterval(t); };
  }, [jobId]);

  const jstr = (h) => { try { return Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join("\n"); } catch { return ""; } };
  const preBox = { background: "var(--bg-2, #11151c)", color: "var(--text-h)", border: "1px solid var(--border)", padding: 10, borderRadius: 6, fontSize: 12, lineHeight: 1.5, maxHeight: 200, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 };

  if (exchanges && exchanges.length > 0) {
    return (
      <div>
        <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 10 }}>
          {exchanges.length} unique requests · {totalSent} total sent (duplicates collapsed) · payload + response captured
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Payload</th><th>×</th></tr></thead>
            <tbody>
              {exchanges.map((r, i) => (
                <React.Fragment key={i}>
                  <tr className="click-row" onClick={() => setExpanded(expanded === i ? null : i)}>
                    <td><span className="badge" style={{ background: methodColor(r.method) + "22", color: methodColor(r.method) }}>{r.method}</span></td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 460, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.url}</td>
                    <td><span style={{ color: r.status >= 200 && r.status < 300 ? "var(--green)" : r.status >= 400 ? "var(--red)" : "var(--text-dim)" }}>{r.status || "-"}</span></td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-dim)" }}>{r.req_body ? String(r.req_body).slice(0, 70) : "-"}</td>
                    <td style={{ fontSize: 11, color: "var(--text-dim)" }}>{r.hits > 1 ? `${r.hits}×` : ""}</td>
                  </tr>
                  {expanded === i && (
                    <tr><td colSpan={5} style={{ padding: 0 }}>
                      <div style={{ padding: 14, background: "var(--bg)", display: "grid", gap: 10 }}>
                        <div><div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-dim)", marginBottom: 3 }}>REQUEST HEADERS</div><pre style={preBox}>{jstr(r.req_headers) || "(none)"}</pre></div>
                        {r.req_body && <div><div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-dim)", marginBottom: 3 }}>PAYLOAD (body sent)</div><pre style={preBox}>{r.req_body}</pre></div>}
                        <div><div style={{ fontSize: 11, fontWeight: 700, color: "var(--text-dim)", marginBottom: 3 }}>RESPONSE {r.status} BODY</div><pre style={preBox}>{r.resp_body || "(empty)"}</pre></div>
                        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>Sent {r.hits}× · last {r.last_seen}</div>
                      </div>
                    </td></tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  if ((requests || []).length === 0) return <div className="empty">No requests captured yet. Attack requests appear here (with payload + response) as the agent sends them.</div>;

  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Type</th></tr></thead>
        <tbody>
          {requests.slice(0, 100).map((r, i) => (
            <React.Fragment key={i}>
              <tr className="click-row" onClick={() => setExpanded(expanded === i ? null : i)}>
                <td><span className="badge" style={{ background: methodColor(r.method) + "22", color: methodColor(r.method) }}>{r.method}</span></td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.url}</td>
                <td>{r.status || "-"}</td>
                <td style={{ fontSize: 12 }}>{r.resource_type || r.content_type || "-"}</td>
              </tr>
              {expanded === i && (
                <tr><td colSpan={4} style={{ padding: 0 }}>
                  <div style={{ padding: 14, background: "var(--bg)" }}>
                    {r.headers && (<><h3>Headers</h3><div className="code-block" style={{ maxHeight: 150 }}>{typeof r.headers === "object" ? Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join("\n") : r.headers}</div></>)}
                    {r.post_data && (<><h3 style={{ marginTop: 10 }}>Body</h3><div className="code-block" style={{ maxHeight: 150 }}>{r.post_data}</div></>)}
                  </div>
                </td></tr>
              )}
            </React.Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}




// Vercel-style log stream: loads the whole log, then appends only NEW lines each
// poll (offset-based) — no "last 300" cap. Freezes on scroll-up so the view
// doesn't jump; auto-tails when pinned to the bottom.
const LOG_MAX_RENDER = 10000; // keep the DOM bounded; full file via Download

function LogsSection({ logRef, jobId }) {
  const [all, setAll] = useState([]);
  const [total, setTotal] = useState(0);
  const [pinBottom, setPinBottom] = useState(true);
  const [frozen, setFrozen] = useState(null); // { lines, total } snapshot while paused
  const offsetRef = useRef(0);

  // Initial full load + incremental streaming of only-new lines.
  useEffect(() => {
    let alive = true;
    offsetRef.current = 0;
    setAll([]); setTotal(0); setFrozen(null); setPinBottom(true);
    api.getScanLogsSince(jobId, 0).then(r => {
      if (!alive) return;
      const lines = r.lines || [];
      setAll(lines.slice(-LOG_MAX_RENDER));
      const t = typeof r.total === "number" ? r.total : lines.length;
      setTotal(t); offsetRef.current = t;
    }).catch(() => {});
    const iv = setInterval(() => {
      api.getScanLogsSince(jobId, offsetRef.current).then(r => {
        if (!alive) return;
        const nu = r.lines || [];
        if (nu.length) {
          setAll(prev => {
            const merged = prev.concat(nu);
            return merged.length > LOG_MAX_RENDER ? merged.slice(-LOG_MAX_RENDER) : merged;
          });
        }
        if (typeof r.total === "number") { setTotal(r.total); offsetRef.current = r.total; }
      }).catch(() => {});
    }, 2500);
    return () => { alive = false; clearInterval(iv); };
  }, [jobId]);

  // Auto-tail when the user is pinned to the bottom.
  useEffect(() => {
    if (pinBottom && !frozen && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [all, pinBottom, frozen]);

  const downloadLogs = async () => {
    try {
      const url = api.getScanLogsDownloadUrl(jobId);
      const res = await fetch(url);
      if (!res.ok) return;
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl; a.download = `scan_${jobId}_logs.txt`; a.click();
      URL.revokeObjectURL(blobUrl);
    } catch {}
  };

  const handleScroll = () => {
    const el = logRef.current; if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setPinBottom(atBottom);
    if (atBottom) setFrozen(null);                       // resumed
    else if (frozen === null) setFrozen({ lines: all, total }); // snapshot on pause
  };

  const resume = () => {
    setPinBottom(true); setFrozen(null);
    requestAnimationFrame(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    });
  };

  const lines = frozen ? frozen.lines : all;            // freeze view while paused
  const newCount = frozen ? Math.max(0, total - (frozen.total || 0)) : 0;
  const truncated = total > all.length;                 // older lines beyond the render cap

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 8 }}>
        <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
          {truncated ? `Showing last ${all.length} of ${total} lines · streaming`
                     : `${total} lines · streaming`}
          {!pinBottom && (
            <span style={{ marginLeft: 8, color: "var(--orange)", fontWeight: 600 }}>
              &#x25B2; Scroll paused{newCount > 0 ? ` · ${newCount} new below` : ""}
            </span>
          )}
        </span>
        <div style={{ display: "flex", gap: 6 }}>
          {!pinBottom && (
            <button className="btn btn-sm" onClick={resume}>
              &#x25BC; Resume{newCount > 0 ? ` (${newCount} new)` : " scroll"}
            </button>
          )}
          <button className="btn btn-sm" onClick={downloadLogs} title="Download full log">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download
          </button>
        </div>
      </div>
      {/* overflowAnchor:none disables the browser's scroll-anchoring. */}
      <div className="log-terminal" ref={logRef} style={{ maxHeight: 600, overflowAnchor: "none" }} onScroll={handleScroll}>
        {truncated && (
          <div style={{ color: "var(--text-dim)", fontSize: 11, fontStyle: "italic", padding: "2px 0" }}>
            … {total - all.length} earlier lines — use Download for the complete log …
          </div>
        )}
        {lines.map((l, i) => {
          const raw = typeof l === "string" ? l.replace(/\x1b\[[0-9;]*m|\[0m/g, "").trimEnd() : String(l);
          return (
            <div key={i} className={`log-line ${classifyLog(raw)}`}>
              {raw}
            </div>
          );
        })}
      </div>
    </div>
  );
}


function HealthIndicator() {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const p = createPoller(() => api.getCanonicalHealth(), setHealth, 5000);
    return () => p.stop();
  }, []);

  if (!health || health.status === "no_health_data") return null;

  const stateColors = { HEALTHY: "#22c55e", DEGRADED: "#ea580c", THROTTLED: "#ef4444", PAUSED: "#6b7280" };
  const color = stateColors[health.state] || "#6b7280";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 14px", background: "var(--bg-surface)",
                  border: `1px solid ${color}33`, borderRadius: "var(--radius-sm)", marginTop: 8, fontSize: 12 }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, flexShrink: 0 }} />
      <span style={{ fontWeight: 600, color, textTransform: "uppercase", letterSpacing: "0.5px", fontSize: 10 }}>
        Target: {health.state || "UNKNOWN"}
      </span>
      {health.avg_latency_ms && (
        <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
          {Math.round(health.avg_latency_ms)}ms avg
        </span>
      )}
      {health.error_5xx_count > 0 && (
        <span style={{ color: "var(--red)", fontFamily: "var(--mono)" }}>
          {health.error_5xx_count} 5xx
        </span>
      )}
      {health.waf_block_count > 0 && (
        <span style={{ color: "var(--orange)", fontFamily: "var(--mono)" }}>
          {health.waf_block_count} WAF blocks
        </span>
      )}
    </div>
  );
}


function classifyLog(l) {
  const msg = typeof l === "string" ? l : "";
  const low = msg.toLowerCase();
  if (low.includes("error") || low.includes("fail") || low.includes("exception")) return "error";
  if (low.includes("warn")) return "warning";
  if (low.includes("found") || low.includes("confirmed") || low.includes("success") || low.includes("vulnerability")) return "success";
  return "info";
}
