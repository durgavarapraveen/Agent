import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { fmtDate } from "./utils";

// LLM I/O log — every request→response, in order. Polls incrementally (via a
// `since` cursor) and appends, so you watch the model conversation unfold live.

const KIND_COLOR = { text: "var(--blue)", json: "var(--purple)", tools: "var(--orange)" };

function Row({ e, open, onToggle }) {
  const color = KIND_COLOR[e.kind] || "var(--text-dim)";
  return (
    <div style={{ borderBottom: "1px solid var(--border,#20242c)" }}>
      <div onClick={onToggle} style={{ display: "flex", gap: 10, padding: "8px 10px", cursor: "pointer", alignItems: "center" }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", width: 26, textAlign: "right" }}>#{e.id}</span>
        <span style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, color: "#0b0c10", background: color, borderRadius: 4, padding: "2px 6px" }}>
          {String(e.kind).toUpperCase()}
        </span>
        <span style={{ flex: 1, minWidth: 0, fontSize: 12, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {(e.prompt || "").slice(0, 120) || "(no prompt)"}
        </span>
        <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
          {e.model} · {e.tokens_in}→{e.tokens_out}t · {e.duration_ms}ms{e.error ? " · ERR" : ""}
        </span>
        <span style={{ fontSize: 14, color: "var(--text-dim)" }}>{open ? "▾" : "▸"}</span>
      </div>
      {open && (
        <div style={{ padding: "4px 12px 12px 12px", fontSize: 12 }}>
          <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>
            {e.provider} · {e.tier} · {e.created_at ? fmtDate(e.created_at) : ""}
            {e.cost_usd ? ` · $${Number(e.cost_usd).toFixed(4)}` : ""}
          </div>
          {e.system_prompt && (
            <>
              <div style={{ fontWeight: 700, color: "var(--text-h)", marginTop: 6 }}>System</div>
              <pre style={preStyle}>{e.system_prompt}</pre>
            </>
          )}
          <div style={{ fontWeight: 700, color: "var(--text-h)", marginTop: 6 }}>Request</div>
          <pre style={preStyle}>{e.prompt || "(empty)"}</pre>
          <div style={{ fontWeight: 700, color: "var(--text-h)", marginTop: 6 }}>Response</div>
          <pre style={{ ...preStyle, color: e.error ? "var(--danger,#d70015)" : "var(--text-h)" }}>
            {e.error ? `ERROR: ${e.error}` : (e.response || "(empty)")}
          </pre>
        </div>
      )}
    </div>
  );
}

const preStyle = {
  whiteSpace: "pre-wrap", wordBreak: "break-word", margin: "2px 0",
  background: "var(--bg-2)", border: "1px solid var(--border)",
  borderRadius: 6, padding: 10, maxHeight: 320, overflow: "auto",
  fontFamily: "var(--mono, ui-monospace, monospace)", fontSize: 12, lineHeight: 1.5,
  color: "var(--text-h)",
};

export default function LlmCallsPanel({ scanId, poll = false }) {
  const [entries, setEntries] = useState([]);
  const [summary, setSummary] = useState({});
  const [openId, setOpenId] = useState(null);
  const sinceRef = useRef(0);
  const seenRef = useRef(new Set());

  useEffect(() => {
    sinceRef.current = 0; seenRef.current = new Set(); setEntries([]);
    let stop = false;
    const tick = async () => {
      const r = await api.getLlmCalls(scanId, sinceRef.current, 200);
      if (stop) return;
      setSummary(r.summary || {});
      const fresh = (r.entries || []).filter(e => !seenRef.current.has(e.id));
      if (fresh.length) {
        fresh.forEach(e => seenRef.current.add(e.id));
        sinceRef.current = Math.max(sinceRef.current, ...fresh.map(e => e.id));
        setEntries(prev => [...prev, ...fresh].slice(-1000)); // chronological order
      }
    };
    tick();
    let iv = null;
    if (poll) iv = setInterval(tick, 2500);
    return () => { stop = true; if (iv) clearInterval(iv); };
  }, [scanId, poll]);

  return (
    <div className="card" style={{ margin: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-h)" }}>LLM I/O</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>Every request → response, in order. Click a row to expand.</div>
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 12, color: "var(--text-dim)" }}>
          <span><b style={{ color: "var(--text-h)" }}>{summary.calls || 0}</b> calls</span>
          <span><b style={{ color: "var(--text-h)" }}>{(summary.tokens_in || 0) + (summary.tokens_out || 0)}</b> tokens</span>
          <span><b style={{ color: "var(--green,#3fb950)" }}>${Number(summary.cost_usd || 0).toFixed(4)}</b></span>
        </div>
      </div>
      <div style={{ maxHeight: 620, overflowY: "auto", border: "1px solid var(--border,#20242c)", borderRadius: 8 }}>
        {entries.length === 0 ? (
          <div style={{ padding: 20, textAlign: "center", color: "var(--text-dim)", fontSize: 13 }}>
            No LLM calls yet — they appear here as the scan queries the model.
          </div>
        ) : (
          entries.map(e => <Row key={e.id} e={e} open={openId === e.id} onToggle={() => setOpenId(openId === e.id ? null : e.id)} />)
        )}
      </div>
    </div>
  );
}
