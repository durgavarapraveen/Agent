import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { fmtDate } from "./utils";

// Shared Agent Blackboard — live cross-agent bus (delta 1).
// Polls /api/scans/{id}/blackboard incrementally (via a `since` cursor) and
// appends new posts. Every agent's creds/findings/tool-results/pivots land here
// in real time, so you can watch agents compounding each other's discoveries.

const KIND_META = {
  finding: { color: "var(--orange)", label: "FINDING" },
  cred:    { color: "var(--red)",    label: "CRED" },
  tool:    { color: "var(--blue)",   label: "TOOL" },
  pivot:   { color: "var(--purple)", label: "PIVOT" },
  note:    { color: "var(--text-dim)", label: "NOTE" },
};

function Chip({ label, value, color }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      minWidth: 78, padding: "8px 12px", borderRadius: 8,
      background: "var(--bg-2, #14161c)", border: "1px solid var(--border, #262a33)",
    }}>
      <span style={{ fontSize: 20, fontWeight: 700, color }}>{value}</span>
      <span style={{ fontSize: 10, letterSpacing: 0.5, color: "var(--text-dim)" }}>{label}</span>
    </div>
  );
}

function Row({ e }) {
  const meta = KIND_META[e.kind] || KIND_META.note;
  const d = e.data || {};
  return (
    <div style={{
      display: "flex", gap: 10, padding: "8px 10px",
      borderBottom: "1px solid var(--border, #20242c)", alignItems: "flex-start",
    }}>
      <span style={{
        flexShrink: 0, fontSize: 10, fontWeight: 700, color: "#0b0c10",
        background: meta.color, borderRadius: 4, padding: "2px 6px", marginTop: 2,
      }}>{meta.label}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, color: "var(--text-h)", wordBreak: "break-word" }}>{e.title}</div>
        <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)", wordBreak: "break-word" }}>
          {d.type ? `${d.type} ` : ""}{d.severity ? `[${d.severity}] ` : ""}
          {d.status ? `${d.status} ` : ""}{d.location || d.login_url || ""}
          {d.result_preview ? ` — ${String(d.result_preview).slice(0, 120)}` : ""}
          {d.username ? ` ${d.username} / ${d.password || ""}` : ""}
        </div>
      </div>
      <div style={{ flexShrink: 0, textAlign: "right", fontSize: 10, color: "var(--text-dim)" }}>
        <div>{e.agent_id || "—"}</div>
        <div>{e.created_at ? fmtDate(e.created_at) : ""}</div>
      </div>
    </div>
  );
}

export default function BlackboardPanel({ scanId, poll = false }) {
  const [entries, setEntries] = useState([]);
  const [summary, setSummary] = useState({});
  const sinceRef = useRef(0);
  const seenRef = useRef(new Set());

  useEffect(() => {
    sinceRef.current = 0;
    seenRef.current = new Set();
    setEntries([]);
    let stop = false;

    const tick = async () => {
      const r = await api.getBlackboard(scanId, sinceRef.current, 300);
      if (stop) return;
      setSummary(r.summary || {});
      const fresh = (r.entries || []).filter(e => !seenRef.current.has(e.id));
      if (fresh.length) {
        fresh.forEach(e => seenRef.current.add(e.id));
        sinceRef.current = Math.max(sinceRef.current, ...fresh.map(e => e.id));
        // newest on top
        setEntries(prev => [...fresh.reverse(), ...prev].slice(0, 500));
      }
    };

    tick();
    let iv = null;
    if (poll) iv = setInterval(tick, 2000);
    return () => { stop = true; if (iv) clearInterval(iv); };
  }, [scanId, poll]);

  const kinds = ["finding", "cred", "tool", "pivot", "note"];

  return (
    <div className="card" style={{ margin: 0 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-h)" }}>Shared Agent Blackboard</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
            Live cross-agent bus — creds, findings, tool-results & pivots as agents post them
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Chip label="TOTAL" value={summary.total || 0} color="var(--cyan)" />
          {kinds.map(k => (
            <Chip key={k} label={KIND_META[k].label} value={summary[k] || 0} color={KIND_META[k].color} />
          ))}
        </div>
      </div>

      <div style={{ maxHeight: 560, overflowY: "auto", border: "1px solid var(--border, #20242c)", borderRadius: 8 }}>
        {entries.length === 0 ? (
          <div style={{ padding: 20, textAlign: "center", color: "var(--text-dim)", fontSize: 13 }}>
            No blackboard posts yet — agents publish here as they discover creds, findings and tool results.
          </div>
        ) : (
          entries.map(e => <Row key={e.id} e={e} />)
        )}
      </div>
    </div>
  );
}
