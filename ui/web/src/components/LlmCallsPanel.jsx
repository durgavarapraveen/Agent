import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { fmtDate } from "./utils";

// LLM I/O log — every request→response, in order. Polls incrementally (via a
// `since` cursor) and appends, so you watch the model conversation unfold live.

// Tinted pill per call kind — soft background + solid foreground (reads in both
// themes, no harsh solid blocks).
const KIND = {
  json:  { fg: "var(--blue,#0a84ff)",   bg: "rgba(10,132,255,0.12)" },
  tools: { fg: "var(--orange,#c2410c)", bg: "rgba(234,88,12,0.14)" },
  text:  { fg: "var(--purple,#7c3aed)", bg: "rgba(124,58,237,0.13)" },
};

// Pretty-print JSON payloads; leave plain text untouched.
function fmtBody(s) {
  const t = (s || "").trim();
  if (!t) return "(empty)";
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try { return JSON.stringify(JSON.parse(t), null, 2); } catch { /* not JSON */ }
  }
  return s;
}

function Field({ label, children, tone }) {
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase",
                    color: "var(--text-dim)", marginBottom: 3 }}>{label}</div>
      <pre style={tone === "error" ? { ...preStyle, color: "var(--danger,#d70015)",
                    borderColor: "var(--danger,#d70015)" } : preStyle}>{children}</pre>
    </div>
  );
}

function Row({ e, open, onToggle }) {
  const k = KIND[e.kind] || KIND.text;
  const [showSys, setShowSys] = useState(false);
  const dur = e.duration_ms >= 1000 ? `${(e.duration_ms / 1000).toFixed(1)}s` : `${e.duration_ms}ms`;
  return (
    <div style={{
      border: "1px solid " + (open ? k.fg : "var(--border,#20242c)"),
      borderRadius: 10, marginBottom: 8, overflow: "hidden",
      background: open ? "var(--bg-1,var(--bg-elev))" : "var(--bg,transparent)",
      boxShadow: open ? "0 1px 4px rgba(0,0,0,0.06)" : "none", transition: "border-color .15s",
    }}>
      <div onClick={onToggle} style={{ display: "flex", gap: 12, padding: "11px 14px", cursor: "pointer", alignItems: "center" }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", width: 42, textAlign: "right", flexShrink: 0 }}>#{e.id}</span>
        <span style={{ flexShrink: 0, width: 52, textAlign: "center", fontSize: 10, fontWeight: 700, letterSpacing: 0.3,
                       color: k.fg, background: k.bg, borderRadius: 999, padding: "3px 0" }}>
          {String(e.kind).toUpperCase()}
        </span>
        <span style={{ flex: 1, minWidth: 0, fontSize: 12.5, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {(e.prompt || "").slice(0, 160) || "(no prompt)"}
        </span>
        {e.error ? (
          <span style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, color: "#fff", background: "var(--danger,#d70015)", borderRadius: 999, padding: "2px 8px" }}>ERROR</span>
        ) : null}
        <span style={{ flexShrink: 0, textAlign: "right", lineHeight: 1.35, minWidth: 118 }}>
          <div style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)" }}>{e.model}</div>
          <div style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--text-dim)" }}>
            {e.tokens_in}→{e.tokens_out}t · {dur}
          </div>
        </span>
        <span style={{ fontSize: 13, color: "var(--text-dim)", flexShrink: 0, width: 12 }}>{open ? "▾" : "▸"}</span>
      </div>
      {open && (
        <div style={{ padding: "0 14px 14px 14px", fontSize: 12, borderTop: "1px solid var(--border,#20242c)", paddingTop: 10 }}>
          <div style={{ color: "var(--text-dim)", fontSize: 11 }}>
            {e.provider} · {e.tier} · {e.created_at ? fmtDate(e.created_at) : ""}
            {e.cost_usd ? ` · $${Number(e.cost_usd).toFixed(4)}` : ""}
          </div>
          {e.system_prompt && (
            <div style={{ marginTop: 10 }}>
              <button onClick={() => setShowSys(s => !s)} style={sysToggleStyle}>
                {showSys ? "▾" : "▸"} System prompt ({e.system_prompt.length.toLocaleString()} chars)
              </button>
              {showSys && <pre style={preStyle}>{e.system_prompt}</pre>}
            </div>
          )}
          <Field label="Request">{fmtBody(e.prompt)}</Field>
          <Field label="Response" tone={e.error ? "error" : undefined}>
            {e.error ? `ERROR: ${e.error}` : fmtBody(e.response)}
          </Field>
        </div>
      )}
    </div>
  );
}

const preStyle = {
  whiteSpace: "pre-wrap", wordBreak: "break-word", margin: "4px 0 0 0",
  background: "var(--bg-2)", border: "1px solid var(--border)",
  borderRadius: 6, padding: 10, maxHeight: 300, overflow: "auto",
  fontFamily: "var(--mono, ui-monospace, monospace)", fontSize: 12, lineHeight: 1.55,
  color: "var(--text-h)",
};

const sysToggleStyle = {
  background: "var(--bg-2)", border: "1px solid var(--border)", borderRadius: 6,
  padding: "5px 10px", fontSize: 11, fontWeight: 600, color: "var(--text)",
  cursor: "pointer", fontFamily: "inherit",
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
      <div style={{ maxHeight: 640, overflowY: "auto", padding: "2px 2px 2px 2px" }}>
        {entries.length === 0 ? (
          <div style={{ padding: 28, textAlign: "center", color: "var(--text-dim)", fontSize: 13,
                        border: "1px dashed var(--border,#20242c)", borderRadius: 10 }}>
            No LLM calls yet — they appear here as the scan queries the model.
          </div>
        ) : (
          entries.slice().reverse().map(e => <Row key={e.id} e={e} open={openId === e.id} onToggle={() => setOpenId(openId === e.id ? null : e.id)} />)
        )}
      </div>
    </div>
  );
}
