import React, { useEffect, useState } from "react";
import { api } from "../api";

export default function Analytics() {
  const [tab, setTab] = useState("coverage");
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState({});

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.getCoverageTracker().catch(() => ({})),
      api.getHonestCoverage().catch(() => ({})),
      api.getSkills().catch(() => ({ skills: [], count: 0 })),
      api.getConfidenceSummary().catch(() => ({})),
      api.getErrorStats().catch(() => ({})),
      api.getCanonicalHealth().catch(() => ({})),
      api.getCanonicalConvergence().catch(() => ({})),
      api.getCanonicalAttackSurface().catch(() => ({})),
      api.getCanonicalLearning().catch(() => ({})),
      api.getDecisionLog().catch(() => []),
      api.getStrategies().catch(() => []),
      api.getExperiences().catch(() => []),
      api.getLlmFailures().catch(() => []),
    ]).then(([tracker, honest, skills, confidence, errors, health, convergence, surface, learning, decisions, strategies, experiences, llmFailures]) => {
      setData({ tracker, honest, skills, confidence, errors, health, convergence, surface, learning, decisions, strategies, experiences, llmFailures });
    }).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading analytics</div>;

  const tabs = [
    { id: "coverage", label: "Coverage" },
    { id: "skills", label: `Skills (${data.skills?.count || 0})` },
    { id: "confidence", label: "Confidence" },
    { id: "health", label: "Target Health" },
    { id: "convergence", label: "Convergence" },
    { id: "errors", label: "Errors & Retries" },
    { id: "decisions", label: `Decisions (${data.decisions?.length || 0})` },
    { id: "strategies", label: `Strategies (${data.strategies?.length || 0})` },
    { id: "llm", label: `LLM Failures (${data.llmFailures?.length || 0})` },
  ];

  return (
    <div>
      <div className="page-header">
        <h1>Analytics & Intelligence</h1>
      </div>

      <div className="tabs" style={{ marginBottom: 16 }}>
        {tabs.map(t => (
          <button key={t.id} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === "coverage" && <CoverageTab tracker={data.tracker} honest={data.honest} />}
      {tab === "skills" && <SkillsTab skills={data.skills} />}
      {tab === "confidence" && <ConfidenceTab data={data.confidence} />}
      {tab === "health" && <HealthTab data={data.health} />}
      {tab === "convergence" && <ConvergenceTab data={data.convergence} />}
      {tab === "errors" && <ErrorsTab data={data.errors} />}
      {tab === "decisions" && <DecisionLogTab data={data.decisions} />}
      {tab === "strategies" && <StrategiesTab strategies={data.strategies} experiences={data.experiences} />}
      {tab === "llm" && <LlmFailuresTab data={data.llmFailures} />}
    </div>
  );
}


function CoverageTab({ tracker, honest }) {
  const report = tracker?.report || {};
  const tests = tracker?.tests || [];
  const cov = honest || {};

  const hasData = tests.length > 0 || Object.keys(cov).length > 0;

  if (!hasData) return <EmptyState msg="No coverage data yet. Run a scan to see honest coverage metrics." />;

  const outcomes = report.outcome_counts || {};
  const failures = report.failure_breakdown || {};
  const total = Object.values(outcomes).reduce((s, v) => s + v, 0);

  return (
    <div>
      <div className="card-grid">
        <StatCard label="Total Tests" value={total} color="var(--accent)" />
        <StatCard label="Confirmed" value={outcomes.CONFIRMED || 0} color="var(--green)" />
        <StatCard label="No Issue" value={outcomes.NO_ISSUE_FOUND || 0} color="var(--blue)" />
        <StatCard label="Ruled Out" value={outcomes.RULED_OUT || 0} color="var(--text-dim)" />
        <StatCard label="Follow Up" value={outcomes.NEEDS_FOLLOW_UP || 0} color="var(--orange)" />
      </div>

      {Object.keys(cov).length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Honest Coverage Summary</h3>
          <div className="code-block" style={{ whiteSpace: "pre-wrap" }}>
            {typeof cov === "string" ? cov : JSON.stringify(cov, null, 2)}
          </div>
        </div>
      )}

      {Object.keys(failures).length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Failure Breakdown</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Object.entries(failures).map(([reason, count]) => (
              <div key={reason} style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text)" }}>{reason}</span>
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
                <tr><th>Category</th><th>Endpoint</th><th>Outcome</th><th>Failure</th><th>Tool</th><th>Status</th></tr>
              </thead>
              <tbody>
                {tests.slice(0, 100).map((t, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 600 }}>{t.category}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.endpoint}</td>
                    <td><span className={`badge ${t.outcome === "CONFIRMED" ? "critical" : t.outcome === "NO_ISSUE_FOUND" ? "confirmed" : "medium"}`}>{t.outcome}</span></td>
                    <td style={{ fontSize: 12, color: t.failure_reason && t.failure_reason !== "NONE" ? "var(--red)" : "var(--text-dim)" }}>{t.failure_reason || "-"}</td>
                    <td style={{ fontSize: 12 }}>{t.tool_name || "-"}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{t.http_status || "-"}</td>
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


function SkillsTab({ skills }) {
  const list = skills?.skills || [];
  if (list.length === 0) return <EmptyState msg="No skills loaded. Add .md files to the skills/ directory." />;

  const categories = [...new Set(list.map(s => s.category))];

  return (
    <div>
      <div className="card-grid">
        <StatCard label="Total Skills" value={list.length} color="var(--accent)" />
        <StatCard label="Categories" value={categories.length} color="var(--cyan)" />
        <StatCard label="Attack Types" value={[...new Set(list.flatMap(s => s.attack_types || []))].length} color="var(--orange)" />
      </div>

      {categories.map(cat => (
        <div key={cat} className="card" style={{ marginTop: 16 }}>
          <h3 style={{ textTransform: "capitalize" }}>{cat}</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {list.filter(s => s.category === cat).map(s => (
              <div key={s.name} style={{ padding: "10px 14px", background: "var(--bg)", borderRadius: 8, border: "1px solid var(--border)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontWeight: 600, color: "var(--text-h)", fontSize: 14 }}>{s.name}</span>
                  {s.severity_range && (
                    <div style={{ display: "flex", gap: 4 }}>
                      {s.severity_range.map(sev => (
                        <span key={sev} className={`badge ${sev.toLowerCase()}`} style={{ fontSize: 10 }}>{sev}</span>
                      ))}
                    </div>
                  )}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>{s.description}</div>
                <div className="pill-row" style={{ marginTop: 6 }}>
                  {(s.attack_types || []).map(at => <span key={at} className="pill" style={{ fontSize: 10 }}>{at}</span>)}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}


function ConfidenceTab({ data }) {
  if (!data || !data.total_findings) return <EmptyState msg="No confidence scoring data yet. Findings are auto-scored after validation." />;

  const pct = data.scored > 0 ? Math.round((data.reportable / data.scored) * 100) : 0;

  return (
    <div>
      <div className="card-grid">
        <StatCard label="Total Findings" value={data.total_findings} color="var(--accent)" />
        <StatCard label="Scored" value={data.scored} color="var(--cyan)" />
        <StatCard label="Avg Confidence" value={`${data.avg_confidence}%`} color="var(--green)" />
      </div>

      <div className="two-col" style={{ marginTop: 16 }}>
        <div className="card" style={{ margin: 0 }}>
          <h3>Confidence Gate Results</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <GateBar label="Reportable" count={data.reportable} total={data.scored} color="var(--green)" />
            <GateBar label="Needs Review" count={data.needs_review} total={data.scored} color="var(--orange)" />
            <GateBar label="Rejected" count={data.rejected} total={data.scored} color="var(--red)" />
            <GateBar label="Unscored" count={data.unscored} total={data.total_findings} color="var(--text-dim)" />
          </div>
        </div>
        <div className="card" style={{ margin: 0 }}>
          <h3>Auto-Report Rate</h3>
          <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "20px 0" }}>
            <span style={{ fontSize: 48, fontWeight: 700, fontFamily: "var(--mono)", color: pct >= 50 ? "var(--green)" : "var(--orange)" }}>{pct}%</span>
            <span style={{ fontSize: 13, color: "var(--text-dim)" }}>of scored findings pass the confidence gate automatically</span>
          </div>
        </div>
      </div>
    </div>
  );
}


function HealthTab({ data }) {
  if (!data || data.status === "no_health_data") return <EmptyState msg="No target health data. Health is tracked during active scans." />;

  const stateColor = { HEALTHY: "var(--green)", DEGRADED: "var(--orange)", THROTTLED: "var(--red)", PAUSED: "var(--text-dim)" };

  return (
    <div>
      <div className="card-grid">
        <StatCard label="State" value={data.state || "UNKNOWN"} color={stateColor[data.state] || "var(--text-dim)"} />
        <StatCard label="Avg Latency" value={data.avg_latency_ms ? `${Math.round(data.avg_latency_ms)}ms` : "-"} color="var(--cyan)" />
        <StatCard label="Requests" value={data.request_count || 0} color="var(--accent)" />
        <StatCard label="5xx Errors" value={data.error_5xx_count || 0} color="var(--red)" />
        <StatCard label="WAF Blocks" value={data.waf_block_count || 0} color="var(--orange)" />
      </div>

      {data.transitions && data.transitions.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>State Transitions</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {data.transitions.map((t, i) => (
              <div key={i} style={{ display: "flex", gap: 12, fontSize: 12, padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                <span style={{ fontFamily: "var(--mono)", color: "var(--text-dim)", minWidth: 160 }}>{t.timestamp || t.time}</span>
                <span style={{ color: stateColor[t.from] }}>{t.from}</span>
                <span style={{ color: "var(--text-dim)" }}>&rarr;</span>
                <span style={{ color: stateColor[t.to], fontWeight: 600 }}>{t.to}</span>
                {t.reason && <span style={{ color: "var(--text-dim)" }}>({t.reason})</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Full Health Data</h3>
        <pre className="code-block" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(data, null, 2)}</pre>
      </div>
    </div>
  );
}


function ConvergenceTab({ data }) {
  if (!data || data.status === "no_convergence_data") return <EmptyState msg="No convergence data. Run a scan to track diminishing returns." />;

  return (
    <div>
      <div className="card-grid">
        <StatCard label="Converged" value={data.converged ? "YES" : "NO"} color={data.converged ? "var(--green)" : "var(--orange)"} />
        <StatCard label="Recommendation" value={data.recommendation || "-"} color="var(--accent)" />
        <StatCard label="New Findings Rate" value={data.new_findings_rate != null ? `${Math.round(data.new_findings_rate * 100)}%` : "-"} color="var(--cyan)" />
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Convergence Details</h3>
        <pre className="code-block" style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(data, null, 2)}</pre>
      </div>
    </div>
  );
}


function ErrorsTab({ data }) {
  return (
    <div>
      <div className="card-grid">
        <StatCard label="Total Attempts" value={data?.total_attempts || 0} color="var(--accent)" />
        <StatCard label="Retries" value={data?.retries || 0} color="var(--orange)" />
        <StatCard label="Recovered" value={data?.recovered || 0} color="var(--green)" />
        <StatCard label="Permanent Failures" value={data?.permanent_failures || 0} color="var(--red)" />
      </div>

      {data?.retries > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Recovery Rate</h3>
          <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "20px 0" }}>
            <span style={{ fontSize: 48, fontWeight: 700, fontFamily: "var(--mono)", color: "var(--green)" }}>
              {data.retries > 0 ? Math.round((data.recovered / data.retries) * 100) : 0}%
            </span>
            <span style={{ fontSize: 13, color: "var(--text-dim)" }}>of retried operations recovered successfully</span>
          </div>
        </div>
      )}

      {data?.by_category && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Errors by Category</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Object.entries(data.by_category).map(([cat, count]) => (
              <div key={cat} style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ color: "var(--text)", textTransform: "uppercase" }}>{cat}</span>
                <span style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


function DecisionLogTab({ data }) {
  if (!data || data.length === 0) return <EmptyState msg="No agent decisions recorded yet." />;

  return (
    <div className="card">
      <h3>Agent Decision Log ({data.length})</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>#</th><th>Phase</th><th>Type</th><th>Decision</th><th>Confidence</th><th>Model</th></tr>
          </thead>
          <tbody>
            {data.slice(0, 100).map((d, i) => (
              <tr key={d.id || i}>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{d.id}</td>
                <td><span className="badge info">{d.phase}</span></td>
                <td style={{ fontSize: 12 }}>{d.decision_type}</td>
                <td style={{ fontSize: 12, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {typeof d.context === "string" ? d.context.slice(0, 100) : JSON.stringify(d.context || d.result || "").slice(0, 100)}
                </td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{d.confidence || "-"}</td>
                <td style={{ fontSize: 11, color: "var(--text-dim)" }}>{d.model_used || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


function StrategiesTab({ strategies, experiences }) {
  return (
    <div>
      {strategies && strategies.length > 0 && (
        <div className="card">
          <h3>Testing Strategies ({strategies.length})</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Test Type</th><th>Description</th><th>Success Rate</th><th>Attempts</th><th>Avg Duration</th><th>Last Used</th></tr>
              </thead>
              <tbody>
                {strategies.map((s, i) => (
                  <tr key={s.strategy_id || i}>
                    <td style={{ fontWeight: 600 }}>{s.test_type}</td>
                    <td style={{ fontSize: 12, maxWidth: 250, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.description}</td>
                    <td>
                      <span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: (s.success_rate || 0) >= 0.5 ? "var(--green)" : "var(--orange)" }}>
                        {Math.round((s.success_rate || 0) * 100)}%
                      </span>
                    </td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{s.total_attempts || 0}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{s.avg_duration_ms ? `${Math.round(s.avg_duration_ms)}ms` : "-"}</td>
                    <td style={{ fontSize: 11, color: "var(--text-dim)" }}>{s.last_used || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {experiences && experiences.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Testing Experiences ({experiences.length})</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Test Type</th><th>Strategy</th><th>Outcome</th><th>Evidence</th><th>Duration</th><th>Error</th></tr>
              </thead>
              <tbody>
                {experiences.slice(0, 50).map((e, i) => (
                  <tr key={e.experience_id || i}>
                    <td style={{ fontWeight: 600, fontSize: 12 }}>{e.test_type}</td>
                    <td style={{ fontSize: 12 }}>{e.strategy_used || "-"}</td>
                    <td><span className={`badge ${e.outcome === "success" ? "confirmed" : e.outcome === "failure" ? "critical" : "medium"}`}>{e.outcome}</span></td>
                    <td style={{ fontSize: 12 }}>{e.evidence_quality || "-"}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{e.duration_ms ? `${e.duration_ms}ms` : "-"}</td>
                    <td style={{ fontSize: 11, color: "var(--red)" }}>{e.error_type || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(!strategies || strategies.length === 0) && (!experiences || experiences.length === 0) && (
        <EmptyState msg="No strategy or experience data yet. The system learns from each scan." />
      )}
    </div>
  );
}


function LlmFailuresTab({ data }) {
  if (!data || data.length === 0) return <EmptyState msg="No LLM failures recorded. This is good!" />;

  const byProvider = {};
  const byType = {};
  data.forEach(f => {
    const key = `${f.provider}/${f.model}`;
    byProvider[key] = (byProvider[key] || 0) + 1;
    byType[f.failure_type || "unknown"] = (byType[f.failure_type || "unknown"] || 0) + 1;
  });

  return (
    <div>
      <div className="card-grid">
        <StatCard label="Total Failures" value={data.length} color="var(--red)" />
        <StatCard label="Providers" value={Object.keys(byProvider).length} color="var(--accent)" />
        <StatCard label="Failure Types" value={Object.keys(byType).length} color="var(--orange)" />
      </div>

      <div className="two-col" style={{ marginTop: 16 }}>
        <div className="card" style={{ margin: 0 }}>
          <h3>By Provider/Model</h3>
          {Object.entries(byProvider).sort((a, b) => b[1] - a[1]).map(([key, count]) => (
            <div key={key} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "4px 0" }}>
              <span style={{ fontFamily: "var(--mono)" }}>{key}</span>
              <span style={{ fontWeight: 700, color: "var(--red)" }}>{count}</span>
            </div>
          ))}
        </div>
        <div className="card" style={{ margin: 0 }}>
          <h3>By Failure Type</h3>
          {Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
            <div key={type} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "4px 0" }}>
              <span>{type}</span>
              <span style={{ fontWeight: 700, color: "var(--red)" }}>{count}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h3>Recent Failures</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Provider</th><th>Model</th><th>Task</th><th>Failure</th><th>Reason</th><th>Tokens</th><th>Time</th></tr>
            </thead>
            <tbody>
              {data.slice(0, 50).map((f, i) => (
                <tr key={f.failure_id || i}>
                  <td style={{ fontSize: 12 }}>{f.provider}</td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{f.model}</td>
                  <td style={{ fontSize: 12 }}>{f.task_type}</td>
                  <td><span className="badge critical" style={{ fontSize: 10 }}>{f.failure_type}</span></td>
                  <td style={{ fontSize: 11, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.failure_reason || "-"}</td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(f.input_tokens || 0) + (f.output_tokens || 0)}</td>
                  <td style={{ fontSize: 11, color: "var(--text-dim)" }}>{f.created_at || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


function StatCard({ label, value, color }) {
  return (
    <div className="stat-card">
      <span className="label">{label}</span>
      <span className="value" style={{ color }}>{value}</span>
    </div>
  );
}

function GateBar({ label, count, total, color }) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
      <span style={{ width: 100, fontWeight: 600, color: "var(--text-dim)" }}>{label}</span>
      <div className="progress-bar-bg" style={{ flex: 1 }}>
        <div className="progress-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span style={{ fontFamily: "var(--mono)", fontWeight: 700, width: 30, textAlign: "right", color }}>{count}</span>
    </div>
  );
}

function EmptyState({ msg }) {
  return (
    <div className="card">
      <div className="empty" style={{ padding: 40 }}>
        <div className="empty-icon" style={{ fontSize: 32 }}>&#9881;</div>
        {msg}
      </div>
    </div>
  );
}
