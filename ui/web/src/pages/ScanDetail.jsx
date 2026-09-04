import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api";
import ActivityLog from "../components/ActivityLog";
import ReconPanel from "../components/ReconPanel";
import { methodColor } from "../components/utils";

export default function ScanDetail() {
  const { scanId } = useParams();
  const [data, setData] = useState(null);
  const [tab, setTab] = useState("overview");
  const [expandedVuln, setExpandedVuln] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getScan(scanId)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <div className="loading">Loading...</div>;
  if (!data) return <div className="empty">Scan not found.</div>;

  const { metadata, vulnerabilities, severity_counts, test_results, context, exploits, scope } = data;

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "vulns", label: `Vulnerabilities (${vulnerabilities.length})` },
    { id: "exploits", label: `Exploits (${exploits.length})` },
    { id: "recon", label: "Recon Data" },
    { id: "tool-outputs", label: "Tool Outputs" },
    { id: "activity", label: "Agent Activity" },
    { id: "requests", label: `Requests (${context.captured_requests?.length || 0})` },
    { id: "logs", label: "Execution Log" },
  ];

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 8 }}>
        <Link to="/scans" style={{ color: "var(--accent)", textDecoration: "none", fontSize: 13 }}>&larr; Back to Scans</Link>
        <div style={{ display: "flex", gap: 8 }}>
          <a href={api.getReportUrl(scanId)} target="_blank" rel="noopener noreferrer"
             className="btn btn-sm" style={{ textDecoration: "none" }}>
            Report (JSON)
          </a>
          <a href={api.getSarifUrl(scanId)} target="_blank" rel="noopener noreferrer"
             className="btn btn-sm" style={{ textDecoration: "none" }}>
            SARIF
          </a>
          <a href={api.getScanLogsDownloadUrl(scanId)} target="_blank" rel="noopener noreferrer"
             className="btn btn-sm" style={{ textDecoration: "none" }}>
            Logs
          </a>
        </div>
      </div>
      <h1>{metadata.target || "Scan"}</h1>

      <div className="tabs">
        {tabs.map((t) => (
          <button key={t.id} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "overview" && <OverviewTab metadata={metadata} severity_counts={severity_counts} test_results={test_results} scope={scope} context={context} vulns={vulnerabilities} />}
      {tab === "vulns" && <VulnsTab vulns={vulnerabilities} expanded={expandedVuln} setExpanded={setExpandedVuln} />}
      {tab === "exploits" && <ExploitsTab exploits={exploits} />}
      {tab === "recon" && <ReconPanel context={context} />}
      {tab === "tool-outputs" && <ToolOutputsTab scanId={scanId} />}
      {tab === "activity" && <ActivityLog scanId={scanId} />}
      {tab === "requests" && <RequestsTab requests={context.captured_requests || []} />}
      {tab === "logs" && <LogsTab scanId={scanId} />}
    </div>
  );
}

/* ── Overview ────────────────────────────────────────────────────────────── */
function OverviewTab({ metadata, severity_counts, test_results, scope, context, vulns }) {
  const confirmed = vulns.filter(v => v.status === "CONFIRMED");
  const totalTests = test_results.passed + test_results.failed + test_results.unconfirmed;
  const passRate = totalTests > 0 ? Math.round((test_results.passed / totalTests) * 100) : 0;

  return (
    <>
      <div className="card-grid">
        <div className="stat-card">
          <span className="label">Duration</span>
          <span className="value">{fmtDur(metadata.duration_seconds)}</span>
        </div>
        <div className="stat-card">
          <span className="label">Agents Spawned</span>
          <span className="value">{metadata.agents_used}</span>
        </div>
        <div className="stat-card">
          <span className="label">Findings</span>
          <span className="value">{vulns.length}</span>
        </div>
        <div className="stat-card">
          <span className="label">Confirmed</span>
          <span className="value" style={{ color: "var(--green)" }}>{test_results.passed}</span>
        </div>
        <div className="stat-card">
          <span className="label">Rejected</span>
          <span className="value" style={{ color: "var(--red)" }}>{test_results.failed}</span>
        </div>
      </div>

      {metadata.token_usage && metadata.token_usage.total_tokens > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>LLM Token Usage</h3>
          <div className="card-grid">
            <div className="stat-card">
              <span className="label">Input Tokens</span>
              <span className="value" style={{ fontSize: 18 }}>{fmtNum(metadata.token_usage.input_tokens)}</span>
            </div>
            <div className="stat-card">
              <span className="label">Output Tokens</span>
              <span className="value" style={{ fontSize: 18 }}>{fmtNum(metadata.token_usage.output_tokens)}</span>
            </div>
            <div className="stat-card">
              <span className="label">Total Tokens</span>
              <span className="value" style={{ fontSize: 18 }}>{fmtNum(metadata.token_usage.total_tokens)}</span>
            </div>
            <div className="stat-card">
              <span className="label">LLM Requests</span>
              <span className="value" style={{ fontSize: 18 }}>{metadata.token_usage.total_requests || 0}</span>
            </div>
            <div className="stat-card">
              <span className="label">Cost</span>
              <span className="value" style={{ fontSize: 18 }}>${(metadata.token_usage.total_cost_usd || 0).toFixed(4)}</span>
            </div>
          </div>
          {(metadata.token_usage.cache_hit_tokens > 0 || metadata.token_usage.reasoning_tokens > 0) && (
            <div className="card-grid" style={{ marginTop: 8 }}>
              {metadata.token_usage.cache_hit_tokens > 0 && (
                <div className="stat-card">
                  <span className="label">Cache Hit</span>
                  <span className="value" style={{ fontSize: 16, color: "var(--green)" }}>{fmtNum(metadata.token_usage.cache_hit_tokens)}</span>
                </div>
              )}
              {metadata.token_usage.cache_miss_tokens > 0 && (
                <div className="stat-card">
                  <span className="label">Cache Miss</span>
                  <span className="value" style={{ fontSize: 16 }}>{fmtNum(metadata.token_usage.cache_miss_tokens)}</span>
                </div>
              )}
              {metadata.token_usage.reasoning_tokens > 0 && (
                <div className="stat-card">
                  <span className="label">Reasoning Tokens</span>
                  <span className="value" style={{ fontSize: 16, color: "var(--purple)" }}>{fmtNum(metadata.token_usage.reasoning_tokens)}</span>
                </div>
              )}
            </div>
          )}
          {metadata.token_usage.provider_breakdown && Object.keys(metadata.token_usage.provider_breakdown).length > 0 && (
            <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-dim)" }}>
              {Object.entries(metadata.token_usage.provider_breakdown).map(([key, val]) => (
                <div key={key} style={{ display: "flex", gap: 16, marginBottom: 4 }}>
                  <span style={{ fontWeight: 600, color: "var(--text)", minWidth: 180 }}>{key}</span>
                  <span>{val.requests} req</span>
                  <span>{fmtNum(val.tokens)} tok</span>
                  <span>${(val.cost || 0).toFixed(4)}</span>
                  {val.cache_hit_tokens > 0 && <span style={{ color: "var(--green)" }}>cache: {fmtNum(val.cache_hit_tokens)}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="two-col">
        <div className="card">
          <h3>Severity Distribution</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
            <SeverityRow label="Critical" count={severity_counts.CRITICAL} total={vulns.length} color="var(--red)" />
            <SeverityRow label="High" count={severity_counts.HIGH} total={vulns.length} color="var(--orange)" />
            <SeverityRow label="Medium" count={severity_counts.MEDIUM} total={vulns.length} color="var(--yellow)" />
            <SeverityRow label="Low" count={severity_counts.LOW} total={vulns.length} color="var(--blue)" />
            <SeverityRow label="Info" count={severity_counts.INFO} total={vulns.length} color="var(--purple)" />
          </div>
        </div>

        <div className="card">
          <h3>Test Results</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 8 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{ fontSize: 32, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--text-h)" }}>{passRate}%</span>
              <span style={{ fontSize: 13, color: "var(--text-dim)" }}>exploit confirmation rate</span>
            </div>
            <div style={{ display: "flex", gap: 16, fontSize: 13 }}>
              <span><span style={{ color: "var(--green)", fontWeight: 600 }}>{test_results.passed}</span> confirmed</span>
              <span><span style={{ color: "var(--red)", fontWeight: 600 }}>{test_results.failed}</span> rejected</span>
              <span><span style={{ color: "var(--orange)", fontWeight: 600 }}>{test_results.unconfirmed}</span> unconfirmed</span>
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Scope</h3>
        <div className="pill-row">
          {(scope.domains || []).map((d, i) => <span key={i} className="pill">{d}</span>)}
        </div>
        {scope.max_tier && <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>Scan depth: {scope.max_tier}</div>}
      </div>

      {context.technologies && Object.keys(context.technologies).length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Technologies Detected</h3>
          {Object.entries(context.technologies).map(([host, techs]) => (
            <div key={host} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 4 }}>{host}</div>
              <div className="pill-row">
                {(Array.isArray(techs) ? techs : []).map((t, i) => <span key={i} className="pill">{t}</span>)}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function SeverityRow({ label, count, total, color }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 13 }}>
      <span style={{ width: 60, fontWeight: 500 }}>{label}</span>
      <div className="progress-bar-bg">
        <div className="progress-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ fontFamily: "var(--mono)", fontWeight: 600, width: 30, textAlign: "right" }}>{count}</span>
    </div>
  );
}

/* ── Vulnerabilities with Filters ────────────────────────────────────────── */
function VulnsTab({ vulns, expanded, setExpanded }) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("severity");

  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const types = [...new Set(vulns.map(v => v.type).filter(Boolean))];

  let filtered = vulns.filter(v => {
    if (sevFilter !== "ALL" && (v.severity || "").toUpperCase() !== sevFilter) return false;
    if (statusFilter !== "ALL" && (v.status || "UNCONFIRMED").toUpperCase() !== statusFilter) return false;
    if (typeFilter !== "ALL" && v.type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (v.title || "").toLowerCase().includes(q) ||
             (v.type || "").toLowerCase().includes(q) ||
             (v.tool || "").toLowerCase().includes(q) ||
             (v.location || "").toLowerCase().includes(q) ||
             (v.details || "").toLowerCase().includes(q);
    }
    return true;
  });

  if (sortBy === "severity") {
    filtered.sort((a, b) => (sevOrder[(a.severity || "INFO").toUpperCase()] || 4) - (sevOrder[(b.severity || "INFO").toUpperCase()] || 4));
  } else if (sortBy === "status") {
    filtered.sort((a, b) => (a.status || "").localeCompare(b.status || ""));
  } else if (sortBy === "confidence") {
    filtered.sort((a, b) => {
      const ca = a._confidence?.score || (a.confidence_score ? a.confidence_score * 100 : 0);
      const cb = b._confidence?.score || (b.confidence_score ? b.confidence_score * 100 : 0);
      return cb - ca;
    });
  }

  return (
    <>
      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search vulnerabilities..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            padding: "6px 12px", borderRadius: 6, border: "1px solid var(--border)",
            background: "var(--bg)", color: "var(--text-h)", fontSize: 13, flex: 1, minWidth: 200,
          }}
        />
        <FilterSelect label="Severity" value={sevFilter} onChange={setSevFilter}
          options={["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]} />
        <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter}
          options={["ALL", "CONFIRMED", "REJECTED", "UNCONFIRMED"]} />
        {types.length > 1 && (
          <FilterSelect label="Type" value={typeFilter} onChange={setTypeFilter}
            options={["ALL", ...types]} />
        )}
        <FilterSelect label="Sort" value={sortBy} onChange={setSortBy}
          options={[
            { value: "severity", label: "Severity" },
            { value: "status", label: "Status" },
            { value: "confidence", label: "Confidence" },
          ]} />
      </div>

      <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>
        Showing {filtered.length} of {vulns.length} findings
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Type</th>
              <th>Tool</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((v, i) => {
              const origIdx = vulns.indexOf(v);
              return (
                <React.Fragment key={origIdx}>
                  <tr className="click-row" onClick={() => setExpanded(expanded === origIdx ? null : origIdx)}>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--accent)" }}>{v.id || `#${origIdx + 1}`}</td>
                    <td style={{ color: "var(--text-h)", fontWeight: 500, maxWidth: 300 }}>{v.title}</td>
                    <td><span className={`badge ${(v.severity || "info").toLowerCase()}`}>{v.severity}</span></td>
                    <td><span className={`badge ${(v.status || "unconfirmed").toLowerCase()}`}>{v.status || "UNCONFIRMED"}</span></td>
                    <td style={{ fontSize: 12 }}>{v.type}</td>
                    <td style={{ fontSize: 12 }}>{v.tool}</td>
                    <td>
                      {v._confidence ? (
                        <span style={{ fontSize: 12, color: v._confidence.level === "HIGH" ? "var(--green)" : "var(--orange)" }}>
                          {v._confidence.score}% {v._confidence.level}
                        </span>
                      ) : v.confidence_score ? (
                        <span style={{ fontSize: 12 }}>{Math.round(v.confidence_score * 100)}%</span>
                      ) : "-"}
                    </td>
                  </tr>
                  {expanded === origIdx && (
                    <tr>
                      <td colSpan={7} style={{ padding: 0 }}>
                        <VulnDetail v={v} />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function FilterSelect({ label, value, onChange, options }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      title={label}
      style={{
        padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)",
        background: "var(--bg)", color: "var(--text-h)", fontSize: 12, cursor: "pointer",
      }}
    >
      {options.map((opt) => {
        const val = typeof opt === "string" ? opt : opt.value;
        const lbl = typeof opt === "string" ? (opt === "ALL" ? `${label}: All` : opt) : opt.label;
        return <option key={val} value={val}>{lbl}</option>;
      })}
    </select>
  );
}

function VulnDetail({ v }) {
  return (
    <div style={{ padding: "16px 20px", background: "var(--bg)", borderTop: "1px solid var(--border)" }}>
      <div className="vuln-detail-grid">
        <span className="lbl">Location</span><span>{v.location || v.target || "-"}</span>
        <span className="lbl">Details</span><span>{v.details || "-"}</span>
        <span className="lbl">Proof</span><span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{v.proof || "-"}</span>
        <span className="lbl">Reproducible</span><span>{v.reproducibility_status || "-"}</span>
        <span className="lbl">Retest</span><span>{v.retest_attempts ? `${v.retest_successes}/${v.retest_attempts} passed` : "-"}</span>
        <span className="lbl">Timestamp</span><span>{v.timestamp || "-"}</span>
      </div>
      {v._confidence?.evidence && (
        <div style={{ marginTop: 12 }}>
          <span className="lbl" style={{ display: "block", marginBottom: 4, color: "var(--text-dim)", fontSize: 12, fontWeight: 600 }}>Confidence Evidence</span>
          <ul style={{ paddingLeft: 16, fontSize: 12, color: "var(--text)" }}>
            {v._confidence.evidence.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}
      {v._dedup && (
        <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-dim)" }}>
          Dedup: {v._dedup.status} | Fingerprint: <code style={{ fontSize: 10 }}>{v._dedup.fingerprint?.slice(0, 16)}...</code>
          {v._dedup.suppressed && <span style={{ color: "var(--orange)", marginLeft: 8 }}>SUPPRESSED</span>}
        </div>
      )}
    </div>
  );
}

/* ── Exploits ────────────────────────────────────────────────────────────── */
function ExploitsTab({ exploits }) {
  if (exploits.length === 0) return <div className="empty">No exploit results for this scan.</div>;
  return (
    <div>
      {exploits.map((ex, i) => {
        // Handle old write-up format (name + content markdown)
        if (ex.content && !ex.type && !ex.vuln_id && !ex.agent) {
          return (
            <div key={i} className="card">
              <h3 style={{ fontFamily: "var(--mono)", fontSize: 13 }}>{ex.name}</h3>
              <div className="code-block" style={{ whiteSpace: "pre-wrap" }}>{ex.content}</div>
            </div>
          );
        }
        // Structured exploit result
        const succeeded = ex.success || ex.exploited || ex.proof_found;
        const title = ex.name || ex.title || ex.vulnerability || ex.vuln_id
          || (ex.type ? `${ex.type} Exploit` : `Exploit #${i + 1}`);
        const target = ex.target || ex.url || ex.location || "-";
        const method = ex.method || ex.technique || ex.type || "-";
        const tool = ex.tool || ex.source || ex.source_agent || ex.agent || ex.sandbox
          || (ex.chain_id ? `Chain ${ex.chain_id}` : "-");
        const proof = ex.proof || ex.output || ex.result || "";
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


/* ── Tool Outputs ───────────────────────────────────────────────────────── */
function ToolOutputsTab({ scanId }) {
  const [outputs, setOutputs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    api.getToolOutputs(scanId)
      .then(setOutputs)
      .catch(() => setOutputs([]))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <div style={{ padding: 16, color: "var(--text-dim)" }}>Loading tool outputs...</div>;
  if (!outputs.length) return <div style={{ padding: 16, color: "var(--text-dim)" }}>No tool outputs recorded for this scan.</div>;

  const tools = [...new Set(outputs.map(o => o.tool_name))];
  const filtered = filter === "ALL" ? outputs : outputs.filter(o => o.tool_name === filter);

  const statusColor = (code) => code === 0 ? "#22c55e" : code === -1 ? "#888" : "#ef4444";
  const statusLabel = (code) => code === 0 ? "OK" : code === -1 ? "?" : `exit ${code}`;

  return (
    <div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
        <button onClick={() => setFilter("ALL")}
          style={{ ...pillBtn, background: filter === "ALL" ? "var(--accent, #6366f1)" : "var(--surface-2, #1e1e2e)", color: filter === "ALL" ? "#fff" : "var(--text-dim)" }}>
          All ({outputs.length})
        </button>
        {tools.map(t => (
          <button key={t} onClick={() => setFilter(t)}
            style={{ ...pillBtn, background: filter === t ? "var(--accent, #6366f1)" : "var(--surface-2, #1e1e2e)", color: filter === t ? "#fff" : "var(--text-dim)" }}>
            {t} ({outputs.filter(o => o.tool_name === t).length})
          </button>
        ))}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {filtered.map((o, i) => {
          const isOpen = expanded === i;
          return (
            <div key={o.id || i} style={{ background: "var(--surface-1, #18181b)", borderRadius: 8, border: "1px solid var(--border, #2e2e3e)" }}>
              <div onClick={() => setExpanded(isOpen ? null : i)}
                style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", cursor: "pointer" }}>
                <span style={{ fontWeight: 600, color: "var(--text)", minWidth: 90 }}>{o.tool_name}</span>
                <span style={{ color: "var(--text-dim)", fontSize: 12, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {o.command || o.operation || o.target}
                </span>
                <span style={{ fontSize: 11, color: statusColor(o.exit_code), fontFamily: "var(--mono)" }}>
                  {statusLabel(o.exit_code)}
                </span>
                {o.duration_s > 0 && <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{o.duration_s.toFixed(1)}s</span>}
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{isOpen ? "▲" : "▼"}</span>
              </div>
              {isOpen && (
                <div style={{ padding: "0 12px 12px" }}>
                  {o.stdout && (
                    <div>
                      <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>stdout ({o.stdout.length} chars)</div>
                      <pre style={{ ...preBoxSD, maxHeight: 400, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{o.stdout}</pre>
                    </div>
                  )}
                  {o.stderr && o.stderr.trim() && (
                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontSize: 11, color: "#ef4444", marginBottom: 4 }}>stderr</div>
                      <pre style={{ ...preBoxSD, maxHeight: 200, whiteSpace: "pre-wrap", wordBreak: "break-all", borderLeft: "3px solid #ef4444" }}>{o.stderr}</pre>
                    </div>
                  )}
                  {!o.stdout && !o.stderr?.trim() && (
                    <div style={{ color: "var(--text-dim)", fontSize: 12 }}>No output captured.</div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const pillBtn = { border: "none", borderRadius: 16, padding: "4px 12px", fontSize: 12, cursor: "pointer" };
const preBoxSD = { background: "var(--surface-2, #0e0e12)", padding: 10, borderRadius: 6, fontSize: 11, maxHeight: 220, overflow: "auto" };

/* ── Requests ────────────────────────────────────────────────────────────── */
function RequestsTab({ requests }) {
  const [expanded, setExpanded] = useState(null);
  const [methodFilter, setMethodFilter] = useState("ALL");

  const methods = [...new Set(requests.map(r => (r.method || "").toUpperCase()).filter(Boolean))];
  const filtered = methodFilter === "ALL" ? requests : requests.filter(r => (r.method || "").toUpperCase() === methodFilter);

  if (requests.length === 0) return <div className="empty">No captured requests.</div>;

  return (
    <>
      <div className="filter-bar" style={{ marginBottom: 12 }}>
        <FilterSelect label="Method" value={methodFilter} onChange={setMethodFilter}
          options={["ALL", ...methods]} />
        <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{filtered.length} requests</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Method</th>
              <th>URL</th>
              <th>Type</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <React.Fragment key={i}>
                <tr className="click-row" onClick={() => setExpanded(expanded === i ? null : i)}>
                  <td><span className="badge" style={{ background: methodColor(r.method) + "22", color: methodColor(r.method) }}>{r.method}</span></td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.url}</td>
                  <td style={{ fontSize: 12 }}>{r.resource_type || "-"}</td>
                  <td>{r.status || "-"}</td>
                </tr>
                {expanded === i && (
                  <tr>
                    <td colSpan={4} style={{ padding: 0 }}>
                      <div style={{ padding: 16, background: "var(--bg)" }}>
                        <h3>Headers</h3>
                        <div className="code-block" style={{ maxHeight: 200 }}>
                          {r.headers ? Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join("\n") : "No headers"}
                        </div>
                        {r.post_data && (
                          <>
                            <h3 style={{ marginTop: 12 }}>Post Data</h3>
                            <div className="code-block">{r.post_data}</div>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/* ── Logs ─────────────────────────────────────────────────────────────────── */
function LogsTab({ scanId }) {
  const [lines, setLines] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getScanLogsFull(scanId)
      .then(r => { setLines(r.lines || []); setTotal(r.total || 0); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <div className="loading">Loading logs...</div>;
  if (lines.length === 0) return <div className="empty">No scan logs found.</div>;

  return (
    <div>
      <div className="flex-between" style={{ marginBottom: 12 }}>
        <span style={{ fontSize: 13, color: "var(--text-dim)" }}>{total.toLocaleString()} lines</span>
        <a href={api.getScanLogsDownloadUrl(scanId)} target="_blank" rel="noopener noreferrer"
           className="btn btn-sm" style={{ textDecoration: "none" }}>
          Download Full Log
        </a>
      </div>
      <pre style={{
        background: "#0d1117", color: "#c9d1d9", padding: 16, borderRadius: "var(--radius-sm)",
        fontSize: 12, fontFamily: "var(--mono)", lineHeight: 1.6, maxHeight: 600,
        overflowY: "auto", overflowX: "auto", whiteSpace: "pre", margin: 0,
      }}>
        {lines.join("\n")}
      </pre>
    </div>
  );
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */
function fmtDur(s) {
  if (!s) return "-";
  const m = Math.floor(s / 60);
  const sec = Math.round(s % 60);
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

function fmtNum(n) {
  if (n == null) return "0";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return String(n);
}
