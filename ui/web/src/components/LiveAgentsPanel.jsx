import React, { useEffect, useState } from "react";
import { api, createPoller } from "../api";

// Injected below AgentCard body — thoughts panel

/**
 * Live Agents — Claude-Code-style view of every parallel sub-agent running for
 * this scan. One card per agent (subdomain scan, OSINT sub-phase, expert probe,
 * cred-chain executor). Shows current tool, current step, steps taken,
 * findings, and cost. Polls every 2s while any agent is running.
 */
export default function LiveAgentsPanel({ scanId, poll = true }) {
  const [state, setState] = useState({ agents: [], counts: {}, count: 0 });

  useEffect(() => {
    if (!scanId) return;
    if (!poll) {
      // One-shot fetch when polling is disabled.
      api.getLiveAgents(scanId)
        .then(r => setState({ agents: r.agents || [], counts: r.counts_by_status || {}, count: r.count || 0 }))
        .catch(() => { });
      return;
    }
    const p = createPoller(
      () => api.getLiveAgents(scanId),
      (r) => setState({ agents: r.agents || [], counts: r.counts_by_status || {}, count: r.count || 0 }),
      2000,
    );
    return () => p.stop();
  }, [scanId, poll]);

  if (state.count === 0) {
    return (
      <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
        No parallel agents dispatched yet.
      </div>
    );
  }

  const groups = groupByPhase(state.agents);

  return (
    <div>
      <StatusBar counts={state.counts} total={state.count} />
      {Object.entries(groups).map(([phase, list]) => (
        <div key={phase} style={{ marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 8 }}>
            <span style={{
              fontSize: 12, fontWeight: 700, letterSpacing: 1, color: "var(--text-dim)",
              textTransform: "uppercase",
            }}>{phase}</span>
            <span style={{ color: "var(--text-dim)", fontSize: 12 }}>({list.length})</span>
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: 10,
          }}>
            {list.map((a) => <AgentCard key={a.id} agent={a} />)}
          </div>
        </div>
      ))}
    </div>
  );
}

function StatusBar({ counts, total }) {
  const items = [
    { key: "running",   label: "Running",   color: "var(--accent, #00ff9a)" },
    { key: "queued",    label: "Queued",    color: "var(--text-dim)" },
    { key: "completed", label: "Completed", color: "var(--text-h)" },
    { key: "failed",    label: "Failed",    color: "var(--red, #ff3355)" },
  ];
  return (
    <div style={{
      display: "flex", gap: 14, alignItems: "center", padding: "10px 14px",
      background: "var(--bg-elev)", border: "1px solid var(--border)",
      borderRadius: 6, marginBottom: 14,
    }}>
      <span style={{ fontWeight: 700, fontSize: 13, letterSpacing: 1 }}>
        {total} PARALLEL AGENTS
      </span>
      {items.map((s) => (
        <span key={s.key} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
          <span style={{
            width: 8, height: 8, borderRadius: 4, background: s.color,
            boxShadow: s.key === "running" ? `0 0 8px ${s.color}` : "none",
          }} />
          <span style={{ color: "var(--text-dim)" }}>{s.label}:</span>
          <span style={{ color: "var(--text-h)", fontFamily: "var(--mono)", fontWeight: 700 }}>
            {counts[s.key] || 0}
          </span>
        </span>
      ))}
    </div>
  );
}

const STATUS_META = {
  running:   { color: "var(--accent, #00ff9a)", label: "RUN"  },
  queued:    { color: "var(--text-dim)",         label: "WAIT" },
  completed: { color: "var(--text-h)",           label: "DONE" },
  failed:    { color: "var(--red, #ff3355)",     label: "FAIL" },
};

function AgentCard({ agent }) {
  const s = STATUS_META[agent.status] || STATUS_META.queued;
  const running = agent.status === "running";
  const elapsed = agent.started_at
    ? Math.max(0, Math.floor((new Date(agent.finished_at || Date.now()) - new Date(agent.started_at)) / 1000))
    : 0;
  const [showThoughts, setShowThoughts] = useState(false);
  const [thoughts, setThoughts] = useState([]);
  useEffect(() => {
    if (!showThoughts) return;
    if (!running) {
      api.getAgentReasoning(agent.scan_id, agent.agent_id, 30)
        .then(r => setThoughts(r.reasoning || []))
        .catch(() => { });
      return;
    }
    const p = createPoller(
      () => api.getAgentReasoning(agent.scan_id, agent.agent_id, 30),
      (r) => setThoughts(r.reasoning || []),
      3000,
    );
    return () => p.stop();
  }, [showThoughts, agent.scan_id, agent.agent_id, running]);
  return (
    <div style={{
      border: `1px solid ${running ? s.color : "var(--border)"}`,
      borderRadius: 6, padding: 12, background: "var(--bg-elev)",
      boxShadow: running ? `0 0 6px ${s.color}22` : "none",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <span style={{
          padding: "2px 7px", borderRadius: 3, fontSize: 10, fontWeight: 700, letterSpacing: 1,
          background: s.color, color: "#000",
        }}>{s.label}</span>
        <span style={{ fontWeight: 700, color: "var(--text-h)", fontSize: 13, wordBreak: "break-all" }}>
          {agent.label || agent.agent_id}
        </span>
      </div>
      {agent.target && (
        <div style={{ color: "var(--text-dim)", fontSize: 11, fontFamily: "var(--mono)",
                      marginBottom: 6, wordBreak: "break-all" }}>
          {agent.target}
        </div>
      )}
      {agent.current_tool && (
        <div style={{ fontSize: 12, marginBottom: 4 }}>
          <span style={{ color: "var(--text-dim)" }}>tool: </span>
          <span style={{ color: "var(--accent, #00ff9a)", fontFamily: "var(--mono)", fontWeight: 700 }}>
            {agent.current_tool}
          </span>
        </div>
      )}
      {agent.current_step && (
        <div style={{
          fontSize: 12, marginBottom: 6, color: "var(--text-h)",
          fontFamily: "var(--mono)", wordBreak: "break-all",
          maxHeight: 40, overflow: "hidden",
        }}>
          {agent.current_step}
        </div>
      )}
      <div style={{ display: "flex", gap: 12, fontSize: 11, color: "var(--text-dim)",
                    borderTop: "1px solid var(--border)", paddingTop: 6 }}>
        <span>steps: <b style={{ color: "var(--text-h)" }}>{agent.steps_taken || 0}</b></span>
        <span>findings: <b style={{ color: "var(--text-h)" }}>{agent.findings_count || 0}</b></span>
        {agent.cost_usd > 0 && (
          <span>cost: <b style={{ color: "var(--text-h)" }}>${(+agent.cost_usd).toFixed(4)}</b></span>
        )}
        <span style={{ marginLeft: "auto" }}>{elapsed}s</span>
        <button onClick={() => setShowThoughts(!showThoughts)}
          style={{ background: "none", border: 0, color: "var(--accent, #00ff9a)",
                    cursor: "pointer", fontSize: 11, padding: 0 }}>
          {showThoughts ? "hide" : "thoughts"}
        </button>
      </div>
      {showThoughts && (
        <div style={{ marginTop: 8, padding: 8, background: "var(--bg)",
                       borderRadius: 4, maxHeight: 200, overflowY: "auto" }}>
          {thoughts.length === 0 && (
            <div style={{ color: "var(--text-dim)", fontSize: 11, fontStyle: "italic" }}>
              No reasoning captured yet…
            </div>
          )}
          {thoughts.map((t) => (
            <ThoughtRow key={t.id} t={t} />
          ))}
        </div>
      )}
    </div>
  );
}

function ThoughtRow({ t }) {
  const [expanded, setExpanded] = React.useState(false);
  const hasDetails = !!(t.tool_args || t.tool_result_preview);
  const status = t.tool_status;
  const statusColor = status == null
    ? "var(--text-dim)"
    : status === 0 ? "#22c55e"
    : status === -1 ? "#ef4444"
    : status >= 200 && status < 300 ? "#22c55e"
    : status >= 300 && status < 400 ? "#eab308"
    : status >= 400 ? "#ef4444"
    : "var(--text-dim)";
  const statusLabel = status == null ? ""
    : status === 0 ? "OK"
    : status === -1 ? "ERR"
    : String(status);
  return (
    <div style={{ padding: "4px 0", borderBottom: "1px dashed var(--border)" }}>
      <div onClick={() => hasDetails && setExpanded(!expanded)}
        style={{ cursor: hasDetails ? "pointer" : "default",
                 display: "flex", gap: 6, alignItems: "baseline" }}>
        <div style={{ fontSize: 10, color: "var(--text-dim)",
                      fontFamily: "var(--mono)", flex: 1 }}>
          #{t.step} · {t.tool_planned || "?"}
          {statusLabel && (
            <span style={{ marginLeft: 8, color: statusColor,
                           fontWeight: 600 }}>{statusLabel}</span>
          )}
          {t.duration_ms != null && (
            <span style={{ marginLeft: 8, color: "var(--text-dim)" }}>
              {t.duration_ms >= 1000
                ? (t.duration_ms / 1000).toFixed(1) + "s"
                : t.duration_ms + "ms"}
            </span>
          )}
        </div>
        {hasDetails && (
          <span style={{ fontSize: 10, color: "var(--text-dim)" }}>
            {expanded ? "▲" : "▼"}
          </span>
        )}
      </div>
      <div style={{ fontSize: 12, color: "var(--text-h)", fontStyle: "italic",
                    wordBreak: "break-word" }}>
        {t.thought}
      </div>
      {expanded && (
        <div style={{ marginTop: 6, borderLeft: "2px solid var(--accent, #6366f1)",
                       paddingLeft: 8, background: "var(--bg)" }}>
          {t.tool_args && Object.keys(t.tool_args).length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: "var(--text-dim)",
                            textTransform: "uppercase", letterSpacing: 0.5,
                            marginBottom: 2 }}>args</div>
              <pre style={{ fontSize: 11, margin: 0, padding: 6,
                            background: "var(--surface-2, #0e0e12)",
                            borderRadius: 4, overflow: "auto", maxHeight: 200,
                            whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {JSON.stringify(t.tool_args, null, 2)}
              </pre>
            </div>
          )}
          {t.tool_result_preview && (
            <div>
              <div style={{ fontSize: 10, color: "var(--text-dim)",
                            textTransform: "uppercase", letterSpacing: 0.5,
                            marginBottom: 2 }}>
                result preview
                {t.tool_result_preview.length >= 4000 && (
                  <span style={{ color: "#eab308", marginLeft: 6 }}>
                    (truncated)
                  </span>
                )}
              </div>
              <pre style={{ fontSize: 11, margin: 0, padding: 6,
                            background: "var(--surface-2, #0e0e12)",
                            borderRadius: 4, overflow: "auto", maxHeight: 300,
                            whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {t.tool_result_preview}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function groupByPhase(agents) {
  const g = {};
  for (const a of agents) {
    const key = a.phase || "other";
    (g[key] = g[key] || []).push(a);
  }
  return g;
}
