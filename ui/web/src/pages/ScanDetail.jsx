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

  const { metadata, vulnerabilities, severity_counts, test_results, context, exploits, scope, executive_summary } = data;

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "vulns", label: `Vulnerabilities (${vulnerabilities.length})` },
    { id: "exploits", label: `Exploits (${exploits.length})` },
    { id: "chains", label: "Attack Chains" },
    { id: "post-exploit", label: "Post-Exploit" },
    { id: "recon", label: "Recon Data" },
    { id: "tool-outputs", label: "Tool Outputs" },
    { id: "activity", label: "Agent Activity" },
    { id: "requests", label: `Requests (${(context.captured_requests?.http_requests?.length || 0) + (context.captured_requests?.tool_executions?.length || 0)})` },
    { id: "coverage", label: "Coverage" },
    { id: "collected", label: "Collected Data" },
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

      {tab === "overview" && <OverviewTab metadata={metadata} severity_counts={severity_counts} test_results={test_results} scope={scope} context={context} vulns={vulnerabilities} executive_summary={executive_summary} />}
      {tab === "vulns" && <VulnsTab vulns={vulnerabilities} expanded={expandedVuln} setExpanded={setExpandedVuln} />}
      {tab === "exploits" && <ExploitsTab exploits={exploits} scanId={scanId} />}
      {tab === "chains" && <AttackChainsTab scanId={scanId} />}
      {tab === "post-exploit" && <PostExploitTab scanId={scanId} />}
      {tab === "recon" && <ReconPanel context={context} scanId={scanId} />}
      {tab === "tool-outputs" && <ToolOutputsTab scanId={scanId} />}
      {tab === "activity" && <ActivityLog scanId={scanId} />}
      {tab === "requests" && <RequestsTab capturedData={context.captured_requests || {}} />}
      {tab === "coverage" && <CoverageTab />}
      {tab === "collected" && <CollectedDataTab scanId={scanId} />}
      {tab === "logs" && <LogsTab scanId={scanId} />}
    </div>
  );
}

/* ── Overview ────────────────────────────────────────────────────────────── */
function OverviewTab({ metadata, severity_counts, test_results, scope, context, vulns, executive_summary }) {
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

      {executive_summary && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Executive Summary</h3>
          <div style={{ fontSize: 13, lineHeight: 1.7, color: "var(--text)", whiteSpace: "pre-wrap" }}>
            {executive_summary.split(/\*\*(.*?)\*\*/g).map((part, i) =>
              i % 2 === 1 ? <strong key={i}>{part}</strong> : <span key={i}>{part}</span>
            )}
          </div>
        </div>
      )}

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
  const [showCritic, setShowCritic] = useState(false);
  const [showCompliance, setShowCompliance] = useState(false);
  const screenshotPath = v.screenshot_path;
  const screenshotFilename = screenshotPath ? screenshotPath.split(/[/\\]/).pop() : null;

  return (
    <div style={{ padding: "16px 20px", background: "var(--bg)", borderTop: "1px solid var(--border)" }}>
      {/* How to Reproduce — plain English for pentesters */}
      <div style={{ marginBottom: 16, padding: 12, background: "var(--surface-1, #1a1a2e)", borderRadius: 8, borderLeft: "3px solid var(--accent)" }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent)", marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>How to Reproduce</div>
        <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text)" }}>
          {v.details || "No reproduction steps available."}
        </div>
        {v.evidence && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-dim)", marginBottom: 4 }}>Evidence</div>
            <pre style={{ fontSize: 12, fontFamily: "var(--mono)", background: "var(--surface-2, #0e0e12)", padding: 8, borderRadius: 4, whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 200, overflow: "auto" }}>{v.evidence}</pre>
          </div>
        )}
        {v.curl_command && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-dim)", marginBottom: 4 }}>cURL Command</div>
            <pre style={{ fontSize: 11, fontFamily: "var(--mono)", background: "#0d1117", color: "#22c55e", padding: 8, borderRadius: 4, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{v.curl_command}</pre>
          </div>
        )}
      </div>

      <div className="vuln-detail-grid">
        <span className="lbl">Location</span><span>{v.location || v.target || "-"}</span>
        <span className="lbl">Target</span><span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{v.target || "-"}</span>
        <span className="lbl">Source</span><span>{v.source || v.tool || "-"}</span>
        {v.cve_id && <><span className="lbl">CVE</span><span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--red)" }}>{v.cve_id}</span></>}
        {v.cwe_id && <><span className="lbl">CWE</span><span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{v.cwe_id}</span></>}
        <span className="lbl">Proof</span><span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{v.proof || "-"}</span>
        <span className="lbl">Reproducible</span>
        <span>
          {v.reproducibility_status === "REPRODUCIBLE"
            ? <span style={{ color: "var(--green)" }}>REPRODUCIBLE</span>
            : v.reproducibility_status || "-"}
        </span>
        <span className="lbl">Retest</span>
        <span>
          {v.retest_attempts
            ? <span>{v.retest_successes}/{v.retest_attempts} passed {v.retest_successes === v.retest_attempts ? <span style={{ color: "var(--green)" }}>(all pass)</span> : ""}</span>
            : "-"}
        </span>
        {v.original_severity && v.original_severity !== (v.severity || "").toLowerCase() && <>
          <span className="lbl">Original Severity</span>
          <span className={`badge ${v.original_severity}`}>{v.original_severity.toUpperCase()}</span>
        </>}
        {v.severity_adjusted_by && <>
          <span className="lbl">Adjusted By</span><span>{v.severity_adjusted_by}</span>
        </>}
      </div>

      {/* Screenshot evidence */}
      {screenshotFilename && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-dim)", marginBottom: 6 }}>Evidence Screenshot</div>
          <img
            src={api.getEvidenceUrl(screenshotFilename)}
            alt="Evidence screenshot"
            style={{ maxWidth: "100%", borderRadius: 6, border: "1px solid var(--border)" }}
            onError={(e) => { e.target.style.display = "none"; }}
          />
        </div>
      )}

      {/* LLM Validation */}
      {v.llm_validation && (
        <div style={{ marginTop: 12, padding: 10, background: "var(--surface-1, #1a1a2e)", borderRadius: 6 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-dim)", marginBottom: 4 }}>LLM Validation</div>
          <div style={{ display: "flex", gap: 12, alignItems: "center", fontSize: 12 }}>
            <span style={{ color: v.llm_validation.validated ? "var(--green)" : "var(--red)", fontWeight: 600 }}>
              {v.llm_validation.validated ? "VALIDATED" : "NOT VALIDATED"}
            </span>
            <span style={{ color: "var(--text-dim)" }}>Confidence: {Math.round((v.llm_validation.raw_confidence || 0) * 100)}%</span>
          </div>
          <div style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>{v.llm_validation.reasoning}</div>
        </div>
      )}

      {/* Critic Analysis — collapsible */}
      {v.critic && (
        <div style={{ marginTop: 12 }}>
          <button onClick={() => setShowCritic(!showCritic)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, color: "var(--accent)", padding: 0 }}>
            {showCritic ? "▼" : "▶"} Critic Analysis — <span style={{ color: v.critic.verdict === "CONFIRMED" ? "var(--green)" : v.critic.verdict === "FALSE_POSITIVE" ? "var(--orange)" : "var(--text-dim)" }}>{v.critic.verdict}</span> ({Math.round((v.critic.confidence || 0) * 100)}%)
          </button>
          {showCritic && (
            <div style={{ marginTop: 8, padding: 10, background: "var(--surface-1, #1a1a2e)", borderRadius: 6, fontSize: 12 }}>
              <div style={{ marginBottom: 8, color: "var(--text)" }}>{v.critic.reasoning}</div>
              {v.critic.false_positive_scenarios?.length > 0 && (
                <div style={{ marginBottom: 8 }}>
                  <div style={{ fontWeight: 600, color: "var(--orange)", marginBottom: 4 }}>False Positive Scenarios</div>
                  <ul style={{ paddingLeft: 16, margin: 0, color: "var(--text-dim)" }}>
                    {v.critic.false_positive_scenarios.map((s, i) => <li key={i} style={{ marginBottom: 2 }}>{s}</li>)}
                  </ul>
                </div>
              )}
              {v.critic.missing_evidence?.length > 0 && (
                <div>
                  <div style={{ fontWeight: 600, color: "var(--red)", marginBottom: 4 }}>Missing Evidence</div>
                  <ul style={{ paddingLeft: 16, margin: 0, color: "var(--text-dim)" }}>
                    {v.critic.missing_evidence.map((s, i) => <li key={i} style={{ marginBottom: 2 }}>{s}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Confidence Evidence */}
      {v._confidence?.evidence && (
        <div style={{ marginTop: 12 }}>
          <span className="lbl" style={{ display: "block", marginBottom: 4, color: "var(--text-dim)", fontSize: 12, fontWeight: 600 }}>Confidence Evidence</span>
          <ul style={{ paddingLeft: 16, fontSize: 12, color: "var(--text)" }}>
            {v._confidence.evidence.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      {/* Compliance Mappings — collapsible */}
      {v._compliance?.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <button onClick={() => setShowCompliance(!showCompliance)} style={{ background: "none", border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, color: "var(--accent)", padding: 0 }}>
            {showCompliance ? "▼" : "▶"} Compliance Mappings ({v._compliance.length} frameworks)
          </button>
          {showCompliance && (
            <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 6 }}>
              {v._compliance.map((c, i) => (
                <div key={i} style={{ padding: 8, background: "var(--surface-1, #1a1a2e)", borderRadius: 6, fontSize: 12 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span className="badge info" style={{ fontSize: 10 }}>{(c.framework || "").toUpperCase()}</span>
                    <span style={{ fontWeight: 600, color: "var(--text-h)" }}>{c.control_id}</span>
                    <span style={{ color: "var(--text)" }}>{c.control_title}</span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>{c.relevance_note}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Dedup info */}
      {v._dedup && (
        <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-dim)" }}>
          Dedup: {v._dedup.status} | Fingerprint: <code style={{ fontSize: 10 }}>{v._dedup.fingerprint?.slice(0, 16)}...</code>
          {v._dedup.suppressed && <span style={{ color: "var(--orange)", marginLeft: 8 }}>SUPPRESSED</span>}
        </div>
      )}

      {v.critic_flag && (
        <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-dim)" }}>
          Flag: <span style={{ color: v.critic_flag === "downgraded_by_critic" ? "var(--orange)" : "var(--text)" }}>{v.critic_flag}</span>
        </div>
      )}

      {v.remediation && (
        <div style={{ marginTop: 12, padding: 12, background: "var(--surface-1, #1a1a2e)", borderRadius: 8, borderLeft: "3px solid var(--green)" }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--green)", marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>Remediation</div>
          <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text)", whiteSpace: "pre-wrap" }}>{v.remediation}</div>
        </div>
      )}
    </div>
  );
}

/* ── Exploits ────────────────────────────────────────────────────────────── */
function ExploitsTab({ exploits, scanId }) {
  const [reports, setReports] = useState([]);
  const [expandedReport, setExpandedReport] = useState(null);

  useEffect(() => {
    api.getExploitReports(scanId).then(setReports).catch(() => []);
  }, [scanId]);

  if (exploits.length === 0 && reports.length === 0) return <div className="empty">No exploit results for this scan.</div>;

  return (
    <div>
      {exploits.map((ex, i) => {
        if (ex.content && !ex.type && !ex.vuln_id && !ex.agent) {
          return (
            <div key={i} className="card">
              <h3 style={{ fontFamily: "var(--mono)", fontSize: 13 }}>{ex.name}</h3>
              <div className="code-block" style={{ whiteSpace: "pre-wrap" }}>{ex.content}</div>
            </div>
          );
        }
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

        // Generate human-readable reproduction steps
        const howTo = _buildHowToReproduce(ex);

        return (
          <div key={i} className="card" style={{ margin: "0 0 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span className={`badge ${succeeded ? "critical" : error ? "medium" : "info"}`}>
                {succeeded ? "EXPLOITED" : error ? "FAILED" : "ATTEMPTED"}
              </span>
              <span style={{ fontWeight: 600, color: "var(--text-h)", fontSize: 14 }}>{title}</span>
              {step && <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{step}</span>}
            </div>

            {/* Human-readable reproduction guide */}
            <div style={{ marginBottom: 12, padding: 12, background: "var(--surface-1, #1a1a2e)", borderRadius: 8, borderLeft: "3px solid var(--accent)" }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "var(--accent)", marginBottom: 6, textTransform: "uppercase", letterSpacing: 1 }}>How a Pentester Can Reproduce This</div>
              <ol style={{ paddingLeft: 20, margin: 0, fontSize: 13, lineHeight: 1.8, color: "var(--text)" }}>
                {howTo.map((s, j) => <li key={j}>{s}</li>)}
              </ol>
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

      {/* Detailed Exploit Reports from markdown files */}
      {reports.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <h3 style={{ color: "var(--text-h)", marginBottom: 12 }}>Detailed Exploit Reports</h3>
          {reports.map((r, i) => (
            <div key={i} className="card" style={{ margin: "0 0 12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, cursor: "pointer" }}
                   onClick={() => setExpandedReport(expandedReport === i ? null : i)}>
                <span className={`badge ${r.outcome?.includes("not confirmed") ? "medium" : r.outcome?.includes("confirmed") ? "critical" : "info"}`}>
                  {r.outcome || "TESTED"}
                </span>
                <span style={{ fontWeight: 600, color: "var(--text-h)", fontSize: 14 }}>{r.agent || r.filename}</span>
                <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{r.target}</span>
                {r.payloads_tested && <span style={{ fontSize: 11, color: "var(--purple)" }}>{r.payloads_tested} payloads</span>}
                <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-dim)" }}>{expandedReport === i ? "▲" : "▼"}</span>
              </div>

              {r.objective && (
                <div style={{ fontSize: 12, color: "var(--text)", marginBottom: 8, padding: "8px 12px", background: "var(--surface-1, #1a1a2e)", borderRadius: 6 }}>
                  <strong style={{ color: "var(--text-dim)" }}>Objective:</strong> {r.objective}
                </div>
              )}

              {r.sections?.["What was done"] && (
                <div style={{ fontSize: 13, color: "var(--text)", marginBottom: 8, padding: "8px 12px", background: "var(--surface-1, #1a1a2e)", borderRadius: 6, borderLeft: "3px solid var(--accent)" }}>
                  <strong style={{ color: "var(--accent)", fontSize: 12 }}>What Was Done:</strong>
                  <div style={{ marginTop: 4 }}>{r.sections["What was done"]}</div>
                </div>
              )}

              {expandedReport === i && (
                <div style={{ marginTop: 8 }}>
                  <div className="vuln-detail-grid" style={{ marginBottom: 12 }}>
                    <span className="lbl">Tier</span><span>{r.tier || "-"}</span>
                    <span className="lbl">Consent</span><span style={{ color: r.consent === "APPROVED" ? "var(--green)" : "var(--red)" }}>{r.consent || "-"}</span>
                    <span className="lbl">Generated</span><span>{r.generated || "-"}</span>
                  </div>

                  {r.activity_log?.length > 0 && (
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-dim)", marginBottom: 6 }}>Activity Log ({r.activity_log.length} steps)</div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Step</th><th>Action</th><th>Payload</th><th>Status</th><th>Analysis</th></tr>
                          </thead>
                          <tbody>
                            {r.activity_log.map((row, j) => (
                              <tr key={j}>
                                <td>{row.step}</td>
                                <td>{row.action}</td>
                                <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 250, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.payload}</td>
                                <td><span className={`badge ${row.status?.includes("200") ? "low" : "medium"}`}>{row.status}</span></td>
                                <td style={{ fontSize: 11, maxWidth: 250, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.analysis}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {r.sections?.Findings && (
                    <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)", fontStyle: "italic" }}>{r.sections.Findings}</div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function _buildHowToReproduce(ex) {
  const steps = [];
  const type = (ex.type || ex.method || "").toLowerCase();
  const target = ex.target || ex.url || ex.location || "the target";
  const chain = ex.chain_id || "";

  if (type.includes("csp") || type.includes("missing_csp")) {
    steps.push(`Open a browser and navigate to ${target}`);
    steps.push("Open Developer Tools (F12) and go to the Network tab");
    steps.push("Reload the page and click on the main document request");
    steps.push("Check the Response Headers for 'Content-Security-Policy'");
    steps.push("If missing, the site has no CSP — try injecting a script tag like <script>alert(1)</script> in any input field");
    steps.push("Without CSP, inline scripts and external script loads are unrestricted");
  } else if (type.includes("cors") || type.includes("missing_cors")) {
    steps.push(`Send a request to ${target} with a custom Origin header: curl -H "Origin: https://evil.com" -v ${target}`);
    steps.push("Check if the response includes 'Access-Control-Allow-Origin: *' or echoes back your origin");
    steps.push("If wildcard CORS, create an HTML page on another domain that fetches data from this API using fetch()");
    steps.push("Check if sensitive data (user info, tokens) can be read cross-origin");
  } else if (type.includes("x_frame") || type.includes("frame") || type.includes("clickjack")) {
    steps.push(`Check response headers: curl -I ${target}`);
    steps.push("Look for 'X-Frame-Options' or CSP 'frame-ancestors' directive");
    steps.push("If missing, create an HTML page with: <iframe src=\"" + target + "\" style=\"opacity:0.1\"></iframe>");
    steps.push("Overlay a button that tricks users into clicking actions on the framed page (clickjacking)");
  } else if (type.includes("sql") || type.includes("injection")) {
    steps.push(`Identify input parameters on ${target} (URL params, form fields, headers)`);
    steps.push("Test with a single quote: add ' to the parameter and check for SQL errors");
    steps.push("Try boolean-based detection: parameter=value' AND 1=1-- vs parameter=value' AND 1=2--");
    steps.push("Use sqlmap for automated exploitation: sqlmap -u \"URL\" --dbs");
  } else {
    steps.push(`Navigate to ${target} and identify the vulnerability type: ${type || "unknown"}`);
    steps.push("Inspect HTTP response headers using curl -v or browser Developer Tools");
    if (ex.error) steps.push(`Note: Previous attempt failed with: ${ex.error}`);
    steps.push("Document findings with screenshots and response headers as evidence");
  }

  if (chain) {
    steps.push(`This is part of attack chain ${chain} — check related exploits in this chain for the full attack path`);
  }

  return steps;
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
function RequestsTab({ capturedData }) {
  const [expanded, setExpanded] = useState(null);
  const [methodFilter, setMethodFilter] = useState("ALL");
  const [section, setSection] = useState("http");

  const httpReqs = capturedData.http_requests || [];
  const toolExecs = capturedData.tool_executions || [];

  const methods = [...new Set(httpReqs.map(r => (r.method || "").toUpperCase()).filter(Boolean))];
  const filtered = methodFilter === "ALL" ? httpReqs : httpReqs.filter(r => (r.method || "").toUpperCase() === methodFilter);

  const toolNames = [...new Set(toolExecs.map(r => (r.tool || r.method || "").toUpperCase()).filter(Boolean))];
  const [toolFilter, setToolFilter] = useState("ALL");
  const filteredTools = toolFilter === "ALL" ? toolExecs : toolExecs.filter(r => (r.tool || r.method || "").toUpperCase() === toolFilter);

  if (httpReqs.length === 0 && toolExecs.length === 0) return <div className="empty">No captured requests.</div>;

  return (
    <>
      <div className="tabs" style={{ marginBottom: 16 }}>
        <button className={`tab ${section === "http" ? "active" : ""}`} onClick={() => { setSection("http"); setExpanded(null); }}>
          HTTP Requests ({httpReqs.length})
        </button>
        <button className={`tab ${section === "tools" ? "active" : ""}`} onClick={() => { setSection("tools"); setExpanded(null); }}>
          Tool Executions ({toolExecs.length})
        </button>
      </div>

      {section === "http" && (
        httpReqs.length === 0 ? (
          <div className="empty" style={{ padding: 24 }}>
            <p style={{ marginBottom: 8 }}>No browser HTTP requests captured.</p>
            <p style={{ fontSize: 12, color: "var(--text-dim)" }}>
              HTTP requests are captured when Playwright/Chromium crawls the target during scanning.
              This happens during the preflight and reconnaissance phases.
              If the target was unreachable during scanning, no requests will appear here.
            </p>
          </div>
        ) : (
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
                    <th>Preflight</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r, i) => (
                    <React.Fragment key={i}>
                      <tr className="click-row" onClick={() => setExpanded(expanded === i ? null : i)}>
                        <td><span className="badge" style={{ background: methodColor(r.method) + "22", color: methodColor(r.method) }}>{r.method}</span></td>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.url}</td>
                        <td style={{ fontSize: 12 }}>{r.resource_type || "-"}</td>
                        <td>
                          <span style={{ color: r.status >= 200 && r.status < 300 ? "var(--green)" : r.status >= 400 ? "var(--red)" : r.status >= 300 ? "var(--yellow)" : "var(--text-dim)" }}>
                            {r.status || "-"}
                          </span>
                        </td>
                        <td>{r.is_preflight ? <span style={{ color: "var(--cyan)" }}>Yes</span> : "-"}</td>
                      </tr>
                      {expanded === i && (
                        <tr>
                          <td colSpan={5} style={{ padding: 0 }}>
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
        )
      )}

      {section === "tools" && (
        <>
          <div className="filter-bar" style={{ marginBottom: 12 }}>
            <FilterSelect label="Tool" value={toolFilter} onChange={setToolFilter}
              options={["ALL", ...toolNames]} />
            <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{filteredTools.length} executions</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Command</th>
                  <th>Status</th>
                  <th>Output</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {filteredTools.map((r, i) => {
                  const bytes = r.stdout_bytes || 0;
                  const sizeStr = bytes > 1024 ? `${(bytes / 1024).toFixed(1)} KB` : bytes > 0 ? `${bytes} B` : "—";
                  const dur = r.duration_s ? `${r.duration_s.toFixed(1)}s` : "-";
                  return (
                  <tr key={i}>
                    <td>
                      <span className="badge" style={{ background: "var(--purple)22", color: "var(--purple)", textTransform: "uppercase", fontWeight: 600 }}>
                        {r.tool || r.method || "-"}
                      </span>
                    </td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {r.command || r.url || "-"}
                    </td>
                    <td>
                      {r.success === true && bytes > 0 ? <span style={{ color: "var(--green)" }}>OK</span>
                        : r.success === true && bytes === 0 ? <span style={{ color: "var(--yellow)" }}>No Output</span>
                        : r.success === false ? <span style={{ color: "var(--red)" }}>Failed</span>
                        : "-"}
                    </td>
                    <td style={{ fontSize: 12, color: bytes > 0 ? "var(--green)" : "var(--text-dim)" }}>
                      {sizeStr}
                    </td>
                    <td style={{ fontSize: 12 }}>{dur}</td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
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

/* ── Coverage ───────────────────────────────────────────────────────────── */
function CoverageTab() {
  const [data, setData] = useState(null);
  const [confidence, setConfidence] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.getCoverageTracker().catch(() => ({})),
      api.getConfidenceSummary().catch(() => ({})),
    ]).then(([c, conf]) => { setData(c); setConfidence(conf); })
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading coverage data...</div>;

  const report = data?.report || {};
  const tests = data?.tests || [];
  const outcomes = report.outcome_counts || {};
  const failures = report.failure_breakdown || {};
  const total = Object.values(outcomes).reduce((s, v) => s + v, 0);

  return (
    <div>
      <div className="card-grid">
        <div className="stat-card">
          <span className="label">Total Tests</span>
          <span className="value">{total}</span>
        </div>
        <div className="stat-card">
          <span className="label">Confirmed</span>
          <span className="value" style={{ color: "var(--green)" }}>{outcomes.CONFIRMED || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">No Issue</span>
          <span className="value" style={{ color: "var(--blue)" }}>{outcomes.NO_ISSUE_FOUND || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">Needs Follow-Up</span>
          <span className="value" style={{ color: "var(--orange)" }}>{outcomes.NEEDS_FOLLOW_UP || 0}</span>
        </div>
      </div>

      {confidence && confidence.total_findings > 0 && (
        <div className="two-col" style={{ marginTop: 16 }}>
          <div className="card" style={{ margin: 0 }}>
            <h3>Confidence Gate</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--green)" }}>Reportable</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{confidence.reportable}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--orange)" }}>Needs Review</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{confidence.needs_review}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--red)" }}>Rejected</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{confidence.rejected}</span>
              </div>
            </div>
          </div>
          <div className="card" style={{ margin: 0 }}>
            <h3>Avg Confidence</h3>
            <div style={{ fontSize: 48, fontWeight: 700, fontFamily: "var(--mono)", color: confidence.avg_confidence >= 70 ? "var(--green)" : "var(--orange)", padding: "12px 0" }}>
              {confidence.avg_confidence}%
            </div>
          </div>
        </div>
      )}

      {Object.keys(failures).length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Failure Reasons</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {Object.entries(failures).map(([reason, count]) => (
              <div key={reason} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "4px 0" }}>
                <span style={{ textTransform: "uppercase", color: "var(--text)" }}>{reason}</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: "var(--red)" }}>{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {tests.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Test Attempts ({tests.length})</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Category</th><th>Endpoint</th><th>Outcome</th><th>Failure</th><th>Tool</th></tr>
              </thead>
              <tbody>
                {tests.slice(0, 50).map((t, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 600, fontSize: 12 }}>{t.category}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.endpoint}</td>
                    <td><span className={`badge ${t.outcome === "CONFIRMED" ? "critical" : t.outcome === "NO_ISSUE_FOUND" ? "confirmed" : "medium"}`}>{t.outcome}</span></td>
                    <td style={{ fontSize: 12, color: t.failure_reason !== "NONE" ? "var(--red)" : "var(--text-dim)" }}>{t.failure_reason || "-"}</td>
                    <td style={{ fontSize: 12 }}>{t.tool_name || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {total === 0 && (!confidence || !confidence.total_findings) && (
        <div className="empty" style={{ padding: 40 }}>No coverage data for this scan.</div>
      )}
    </div>
  );
}


/* ── Collected Data (transparency) ─────────────────────────────────────── */
function CollectedDataTab({ scanId }) {
  const [data, setData] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getCollectedData(scanId).then(setData).catch(() => null).finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <div className="loading">Loading collected data inventory...</div>;
  if (!data) return <div className="empty">Unable to load data inventory.</div>;

  const tables = data.tables || {};
  const tableNames = Object.keys(tables);
  const totalRows = tableNames.reduce((s, k) => s + (tables[k].count || 0), 0);

  return (
    <div>
      <div className="card" style={{ marginBottom: 16, padding: 16, borderLeft: "3px solid var(--accent)" }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-h)", marginBottom: 4 }}>Data Transparency</div>
        <div style={{ fontSize: 13, color: "var(--text)" }}>
          Every piece of data collected during this scan is stored in PostgreSQL.
          Below is a complete inventory of {tableNames.length} database tables containing {totalRows} total rows for this scan.
          Click any table to inspect its contents.
        </div>
      </div>

      {tableNames.map((tableName) => {
        const t = tables[tableName];
        const isOpen = expanded === tableName;
        const hasData = t.data && t.data.length > 0;
        const hasKeys = t.keys && t.keys.length > 0;

        return (
          <div key={tableName} className="card" style={{ margin: "0 0 8px", padding: 0 }}>
            <div
              onClick={() => setExpanded(isOpen ? null : tableName)}
              style={{
                padding: "12px 16px", cursor: "pointer", display: "flex",
                justifyContent: "space-between", alignItems: "center",
                borderBottom: isOpen ? "1px solid var(--border)" : "none",
              }}
            >
              <div>
                <span style={{ fontFamily: "var(--mono)", fontSize: 13, fontWeight: 600, color: "var(--text-h)" }}>
                  {tableName}
                </span>
                <span style={{ fontSize: 12, color: "var(--text-dim)", marginLeft: 10 }}>
                  {t.description}
                </span>
              </div>
              <span className={`badge ${t.count > 0 ? "info" : "low"}`}>{t.count} rows</span>
            </div>

            {isOpen && (
              <div style={{ padding: 12, maxHeight: 400, overflowY: "auto" }}>
                {hasData ? (
                  <table className="mini-table" style={{ width: "100%", fontSize: 12 }}>
                    <thead>
                      <tr>
                        {Object.keys(t.data[0]).filter(k => k !== "extra" && k !== "details").slice(0, 8).map((col) => (
                          <th key={col} style={{ textAlign: "left", padding: "4px 8px", color: "var(--text-dim)", borderBottom: "1px solid var(--border)" }}>
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {t.data.slice(0, 50).map((row, i) => (
                        <tr key={i}>
                          {Object.keys(t.data[0]).filter(k => k !== "extra" && k !== "details").slice(0, 8).map((col) => (
                            <td key={col} style={{ padding: "4px 8px", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", borderBottom: "1px solid var(--border)" }}>
                              {typeof row[col] === "object" ? JSON.stringify(row[col]).slice(0, 80) : String(row[col] ?? "")}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : hasKeys ? (
                  <div style={{ fontSize: 12, color: "var(--text)" }}>
                    <strong>Data sections:</strong> {t.keys.join(", ")}
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
                    {t.count > 0 ? "Data available via dedicated tab." : "No data collected for this table."}
                  </div>
                )}
                {hasData && t.data.length > 50 && (
                  <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 8 }}>
                    Showing first 50 of {t.data.length} rows.
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}


/* ── Attack Chains ──────────────────────────────────────────────────────── */
function AttackChainsTab({ scanId }) {
  const [chains, setChains] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    api.getAttackChains(scanId).then(d => setChains(Array.isArray(d) ? d : []))
      .catch(() => {}).finally(() => setLoading(false));
  }, [scanId]);
  if (loading) return <div className="loading">Loading...</div>;
  if (!chains.length) return <div className="empty">No attack chains detected.</div>;
  return (
    <div>
      {chains.map((c, i) => {
        const steps = Array.isArray(c.steps) ? c.steps : [];
        return (
          <div key={i} className="card" style={{ marginBottom: 12 }}>
            <div className="flex-between" style={{ marginBottom: 8 }}>
              <h3 style={{ margin: 0, fontSize: 14 }}>Chain #{i + 1}: {c.description || c.chain_id || "Unknown"}</h3>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className={`badge ${c.status === "completed" ? "high" : "info"}`}>{c.status}</span>
                <span style={{ fontSize: 12, color: "var(--text-dim)" }}>Score: {(c.score || 0).toFixed(2)}</span>
              </div>
            </div>
            {c.impact && <div style={{ fontSize: 12, color: "var(--orange)", marginBottom: 8 }}>{c.impact}</div>}
            <div style={{ display: "flex", gap: 4, alignItems: "center", flexWrap: "wrap" }}>
              {steps.map((s, si) => {
                const label = typeof s === "string" ? s : (s.type || s.vuln_type || s.title || s.vuln_id || "?");
                const loc = typeof s === "object" ? (s.location || "") : "";
                return (
                  <React.Fragment key={si}>
                    <div style={{ padding: "6px 12px", background: "var(--surface-1, #1e3a5f)", borderRadius: 6, fontSize: 12, color: "#fff" }}>
                      <div style={{ fontWeight: 600 }}>{label}</div>
                      {loc && <div style={{ fontSize: 10, opacity: 0.7 }}>{loc}</div>}
                    </div>
                    {si < steps.length - 1 && <span style={{ color: "var(--accent)", fontSize: 16 }}>→</span>}
                  </React.Fragment>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ── Post-Exploit ──────────────────────────────────────────────────────── */
function PostExploitTab({ scanId }) {
  const [data, setData] = useState([]);
  const [meta, setMeta] = useState({});
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    Promise.all([
      api.getPostExploit(scanId).then(d => setData(Array.isArray(d) ? d : [])).catch(() => {}),
      api.getScanMetadata(scanId).then(d => setMeta(d || {})).catch(() => {}),
    ]).finally(() => setLoading(false));
  }, [scanId]);
  if (loading) return <div className="loading">Loading...</div>;

  const grouped = {};
  data.forEach(d => {
    const t = d.data_type || "other";
    if (!grouped[t]) grouped[t] = [];
    grouped[t].push(d);
  });

  const typeLabels = { privesc: "Privilege Escalation", credentials: "Harvested Credentials", lateral_movement: "Lateral Movement", persistence: "Persistence Mechanisms" };
  const mitreData = meta.mitre_mappings;
  const mitreMappings = Array.isArray(mitreData) ? mitreData : [];

  const hasData = data.length > 0 || mitreMappings.length > 0;
  if (!hasData) return <div className="empty">No post-exploitation data collected.</div>;

  return (
    <div>
      {Object.entries(grouped).map(([type, items]) => (
        <div key={type} className="card" style={{ marginBottom: 12 }}>
          <h3 style={{ margin: "0 0 8px", fontSize: 14 }}>{typeLabels[type] || type} ({items.length})</h3>
          <table className="table"><thead><tr><th>Title</th><th>Details</th><th>Found At</th></tr></thead><tbody>
            {items.map((item, i) => (
              <tr key={i}>
                <td style={{ fontWeight: 500 }}>{item.title || "-"}</td>
                <td style={{ fontSize: 12, fontFamily: "var(--mono)", maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {typeof item.details === "object" ? JSON.stringify(item.details).slice(0, 200) : String(item.details || "").slice(0, 200)}
                </td>
                <td style={{ fontSize: 11, color: "var(--text-dim)" }}>{item.created_at ? new Date(item.created_at).toLocaleString() : "-"}</td>
              </tr>
            ))}
          </tbody></table>
        </div>
      ))}

      {mitreMappings.length > 0 && (
        <div className="card" style={{ marginBottom: 12 }}>
          <h3 style={{ margin: "0 0 8px", fontSize: 14 }}>MITRE ATT&CK Mappings ({mitreMappings.length})</h3>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {mitreMappings.map((m, i) => (
              <div key={i} style={{ padding: "6px 10px", background: "var(--surface-1, #1a1a2e)", borderRadius: 6, fontSize: 12 }}>
                <span style={{ fontWeight: 600, color: "var(--accent)" }}>{m.technique_id || "?"}</span>
                <span style={{ marginLeft: 6, color: "var(--text)" }}>{m.name || ""}</span>
                {m.tactic && <span style={{ marginLeft: 6, color: "var(--text-dim)", fontSize: 10 }}>({m.tactic})</span>}
              </div>
            ))}
          </div>
        </div>
      )}
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
