import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { fmtDate } from "./utils";

// Jev Decisions — every typed decision Jev (System-One) made, in order. Polls
// incrementally (via a `since` cursor) and appends, so you watch the classifier's
// decisions unfold live. Each row = one question → typed answer + probability.

const SITE_COLOR = {
  routing: "var(--blue)",
  phase_gate: "var(--orange)",
  tool_gate: "var(--danger,#d70015)",
  triage: "var(--purple)",
  validate: "var(--green,#3fb950)",
};
const SITE_LABEL = {
  routing: "ROUTE", phase_gate: "PHASE", tool_gate: "GATE", triage: "TRIAGE",
  validate: "VALID",
};

function probColor(p) {
  if (p >= 0.8) return "var(--green,#3fb950)";
  if (p >= 0.5) return "var(--orange,#d29922)";
  return "var(--danger,#d70015)";
}

function Row({ e, open, onToggle }) {
  const color = SITE_COLOR[e.site] || "var(--text-dim)";
  const p = Number(e.probability || 0);
  return (
    <div style={{ borderBottom: "1px solid var(--border,#20242c)" }}>
      <div onClick={onToggle} style={{ display: "flex", gap: 10, padding: "8px 10px", cursor: "pointer", alignItems: "center" }}>
        <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", width: 26, textAlign: "right" }}>#{e.id}</span>
        <span style={{ flexShrink: 0, fontSize: 10, fontWeight: 700, color: "#0b0c10", background: color, borderRadius: 4, padding: "2px 6px", width: 54, textAlign: "center" }}>
          {SITE_LABEL[e.site] || String(e.site || "?").toUpperCase()}
        </span>
        <span style={{ flexShrink: 0, fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--mono)", width: 42 }}>
          {String(e.decision_type || "").toUpperCase()}
        </span>
        <span style={{ flex: 1, minWidth: 0, fontSize: 12, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {(e.question || "").slice(0, 100) || "(no question)"}
        </span>
        <span style={{ flexShrink: 0, fontSize: 12, fontWeight: 700, color: "var(--text-h)", fontFamily: "var(--mono)" }}>
          {String(e.value)}
        </span>
        <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 700, color: probColor(p), fontFamily: "var(--mono)", width: 44, textAlign: "right" }}>
          {(p * 100).toFixed(0)}%
        </span>
        <span style={{ fontSize: 14, color: "var(--text-dim)" }}>{open ? "▾" : "▸"}</span>
      </div>
      {open && (
        <div style={{ padding: "4px 12px 12px 12px", fontSize: 12 }}>
          <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>
            {e.site} · {e.decision_type} · {e.model} · {e.duration_ms}ms
            {e.created_at ? ` · ${fmtDate(e.created_at)}` : ""}
            {e.error ? " · ERR" : ""}
          </div>
          <div style={{ fontWeight: 700, color: "var(--text-h)", marginTop: 6 }}>Question</div>
          <pre style={preStyle}>{e.question || "(empty)"}</pre>
          <div style={{ fontWeight: 700, color: "var(--text-h)", marginTop: 6 }}>State evaluated</div>
          <pre style={preStyle}>{e.state_preview || "(empty)"}</pre>
          <div style={{ fontWeight: 700, color: "var(--text-h)", marginTop: 6 }}>Decision</div>
          <pre style={{ ...preStyle, color: e.error ? "var(--danger,#d70015)" : "var(--text-h)" }}>
            {e.error ? `ERROR: ${e.error}` : `${e.value}  (probability ${(p * 100).toFixed(1)}%)`}
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

export default function JevDecisionsPanel({ scanId, poll = false }) {
  const [entries, setEntries] = useState([]);
  const [summary, setSummary] = useState({});
  const [openId, setOpenId] = useState(null);
  const sinceRef = useRef(0);
  const seenRef = useRef(new Set());

  useEffect(() => {
    sinceRef.current = 0; seenRef.current = new Set(); setEntries([]);
    let stop = false;
    const tick = async () => {
      const r = await api.getJevDecisions(scanId, sinceRef.current, 200);
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

  const bySite = summary.by_site || {};
  return (
    <div className="card" style={{ margin: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-h)" }}>Jev Decisions</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>Every typed decision Jev made, in order. Click a row to expand.</div>
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 12, color: "var(--text-dim)", flexWrap: "wrap" }}>
          <span><b style={{ color: "var(--text-h)" }}>{summary.decisions || 0}</b> decisions</span>
          <span>avg <b style={{ color: "var(--text-h)" }}>{((summary.avg_probability || 0) * 100).toFixed(0)}%</b></span>
          {Object.keys(bySite).map(s => (
            <span key={s} style={{ color: SITE_COLOR[s] || "var(--text-dim)" }}>
              <b>{bySite[s]}</b> {SITE_LABEL[s] || s}
            </span>
          ))}
        </div>
      </div>
      <div style={{ maxHeight: 620, overflowY: "auto", border: "1px solid var(--border,#20242c)", borderRadius: 8 }}>
        {entries.length === 0 ? (
          <div style={{ padding: 20, textAlign: "center", color: "var(--text-dim)", fontSize: 13 }}>
            No Jev decisions yet — they appear here as the scan uses Jev (enable with the NEO_JEV_* flags).
          </div>
        ) : (
          entries.slice().reverse().map(e => <Row key={e.id} e={e} open={openId === e.id} onToggle={() => setOpenId(openId === e.id ? null : e.id)} />)
        )}
      </div>
    </div>
  );
}
