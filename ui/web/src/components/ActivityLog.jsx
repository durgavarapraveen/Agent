import { useEffect, useState } from "react";
import { api } from "../api";

const ACTION_COLORS = {
  phase: "#6366f1", tool_run: "#3b82f6", finding: "#22c55e", retest: "#f59e0b",
  critic: "#ef4444", exploit: "#ec4899", credential: "#8b5cf6", injection: "#14b8a6",
  browser: "#06b6d4", error: "#ef4444", decision: "#a78bfa",
};

const ACTION_ICONS = {
  phase: "◆", tool_run: "▶", finding: "✦", retest: "↻", critic: "⊘",
  exploit: "⚡", credential: "🔑", injection: "💉", browser: "🌐",
  error: "✗", decision: "⊙",
};

const pillStyle = { border: "none", borderRadius: 16, padding: "4px 12px", fontSize: 12, cursor: "pointer" };
const preBox = { background: "var(--surface-2, #0e0e12)", padding: 10, borderRadius: 6, fontSize: 11, maxHeight: 220, overflow: "auto" };

function fmtTs(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function ActivityLog({ scanId, poll = false }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [filter, setFilter] = useState("ALL");

  useEffect(() => {
    const load = () => {
      api.getActivity(scanId)
        .then(setItems)
        .catch(() => setItems([]))
        .finally(() => setLoading(false));
    };
    load();
    if (poll) {
      const iv = setInterval(load, 8000);
      return () => clearInterval(iv);
    }
  }, [scanId, poll]);

  if (loading) return <div style={{ padding: 16, color: "var(--text-dim)" }}>Loading activity log...</div>;
  if (!items.length) return <div style={{ padding: 16, color: "var(--text-dim)" }}>No agent activity recorded for this scan.</div>;

  const actions = [...new Set(items.map(a => a.action))];
  const filtered = filter === "ALL" ? items : items.filter(a => a.action === filter);

  return (
    <div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
        <button onClick={() => setFilter("ALL")}
          style={{ ...pillStyle, background: filter === "ALL" ? "var(--accent, #6366f1)" : "var(--surface-2, #1e1e2e)", color: filter === "ALL" ? "#fff" : "var(--text-dim)" }}>
          All ({items.length})
        </button>
        {actions.map(a => (
          <button key={a} onClick={() => setFilter(a)}
            style={{ ...pillStyle, background: filter === a ? (ACTION_COLORS[a] || "#888") : "var(--surface-2, #1e1e2e)", color: filter === a ? "#fff" : "var(--text-dim)" }}>
            {ACTION_ICONS[a] || "●"} {a.replace("_", " ")} ({items.filter(x => x.action === a).length})
          </button>
        ))}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        {filtered.map((a, i) => {
          const isOpen = expanded === i;
          const color = ACTION_COLORS[a.action] || "#888";
          const icon = ACTION_ICONS[a.action] || "●";
          return (
            <div key={a.id || i} style={{ background: "var(--surface-1, #18181b)", borderRadius: 8, border: "1px solid var(--border, #2e2e3e)" }}>
              <div onClick={() => setExpanded(isOpen ? null : i)}
                style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", cursor: "pointer" }}>
                <span style={{ color, fontSize: 14, minWidth: 18, textAlign: "center" }}>{icon}</span>
                <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)", minWidth: 70 }}>{fmtTs(a.timestamp)}</span>
                {a.phase && <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 8, background: "rgba(99,102,241,0.15)", color: "#818cf8" }}>{a.phase}</span>}
                <span style={{ fontWeight: 600, color: "var(--text)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.title}</span>
                {a.tool && <span style={{ fontSize: 11, color: "var(--cyan, #22d3ee)", fontFamily: "var(--mono)" }}>{a.tool}</span>}
                {a.status && a.status !== "ok" && (
                  <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 8,
                    background: a.status === "error" ? "rgba(239,68,68,0.15)" : "rgba(245,158,11,0.15)",
                    color: a.status === "error" ? "#ef4444" : "#f59e0b" }}>{a.status}</span>
                )}
                {a.duration_s > 0 && <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{a.duration_s.toFixed(1)}s</span>}
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{isOpen ? "▲" : "▼"}</span>
              </div>
              {isOpen && (
                <div style={{ padding: "0 12px 12px" }}>
                  {a.detail && <div style={{ fontSize: 12, color: "var(--text)", marginBottom: 8 }}>{a.detail}</div>}
                  {a.target && <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>Target: <span style={{ color: "var(--text)", fontFamily: "var(--mono)" }}>{a.target}</span></div>}
                  {a.input_data && (
                    <div style={{ marginBottom: 8 }}>
                      <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>Input</div>
                      <pre style={{ ...preBox, maxHeight: 200, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{a.input_data}</pre>
                    </div>
                  )}
                  {a.output_data && (
                    <div>
                      <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>Output</div>
                      <pre style={{ ...preBox, maxHeight: 400, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{a.output_data}</pre>
                    </div>
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
