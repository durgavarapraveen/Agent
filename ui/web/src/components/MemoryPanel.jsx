import React, { useEffect, useState } from "react";
import { api } from "../api";
import { fmtDate } from "./utils";

// Per-scan memory viewer — shows exactly what the agent + Ask(LLM) chat use:
// the recorded phase-by-phase reasoning (scan_llm_memory) and the fact index
// (findings / access / recon) that is fed to the model. Read-only.

const pre = {
  margin: "6px 0 0 0", padding: 10, background: "var(--bg-2)", color: "var(--text-h)",
  border: "1px solid var(--border)", borderRadius: 6, maxHeight: 320, overflow: "auto",
  fontFamily: "var(--mono, ui-monospace, monospace)", fontSize: 12, lineHeight: 1.55,
  whiteSpace: "pre-wrap", wordBreak: "break-word",
};

export default function MemoryPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("reasoning");

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    api.getScanMemory(scanId)
      .then((d) => setData(d || {}))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <div style={{ padding: 16, color: "var(--text-dim)" }}>Loading scan memory…</div>;
  const mem = (data && data.phase_memory) || [];
  const facts = (data && data.fact_index) || {};
  const counts = (data && data.counts) || {};

  return (
    <div className="card" style={{ margin: 0 }}>
      <div style={{ marginBottom: 8 }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-h)" }}>Scan Memory</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          What the agent recorded and the Ask (LLM) chat reads back. Read-only.
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, fontSize: 12, color: "var(--text-dim)", marginBottom: 10, flexWrap: "wrap" }}>
        <span><b style={{ color: "var(--text-h)" }}>{counts.phase_memory_entries ?? mem.length}</b> reasoning entries</span>
        <span><b style={{ color: "var(--text-h)" }}>{counts.findings_indexed ?? 0}</b> findings indexed</span>
        <span><b style={{ color: "var(--text-h)" }}>{counts.access_indexed ?? 0}</b> access records</span>
      </div>

      <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
        {[["reasoning", "Recorded reasoning"], ["facts", "Fact index (fed to LLM)"]].map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)}
            style={{
              padding: "5px 12px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer",
              border: "1px solid " + (tab === id ? "var(--accent)" : "var(--border)"),
              background: tab === id ? "var(--accent)" : "var(--bg-2)",
              color: tab === id ? "var(--accent-on,#fff)" : "var(--text)",
            }}>{label}</button>
        ))}
      </div>

      {tab === "reasoning" && (
        mem.length === 0 ? (
          <div style={{ padding: 20, textAlign: "center", color: "var(--text-dim)", fontSize: 13,
                        border: "1px dashed var(--border)", borderRadius: 10 }}>
            No recorded reasoning for this scan (phase summaries are written as the scan runs).
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {mem.map((m, i) => (
              <div key={m.id ?? i} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: "10px 12px" }}>
                <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                  <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: 0.3, color: "var(--accent)",
                                 background: "var(--bg-2)", borderRadius: 999, padding: "2px 8px" }}>
                    {(m.phase || "phase").toUpperCase()}
                  </span>
                  {m.kind && <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{m.kind}</span>}
                  {m.tool && <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>{m.tool}</span>}
                  <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-dim)" }}>
                    {m.created_at ? fmtDate(m.created_at) : ""}
                  </span>
                </div>
                <pre style={pre}>{m.content || "(empty)"}</pre>
              </div>
            ))}
          </div>
        )
      )}

      {tab === "facts" && (
        <div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4 }}>
            This is the compact fact index injected into the chat prompt (per-finding proof preview included).
          </div>
          <pre style={{ ...pre, maxHeight: 560 }}>{JSON.stringify(facts, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
