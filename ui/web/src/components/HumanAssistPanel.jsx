import React, { useEffect, useState } from "react";
import { api } from "../api";
import { fmtDate } from "./utils";

// Human-in-the-loop assist — the scanner offloads tasks it can't solve alone
// (client-side puzzles, OSINT, business logic, CAPTCHA) here. A human answers;
// "Mark solved" makes the item count as confirmed in the benchmark score.

function RequestCard({ scanId, req, onDone }) {
  const [answer, setAnswer] = useState(req.answer || "");
  const [solved, setSolved] = useState(!!req.solved);
  const [busy, setBusy] = useState(false);
  const answered = req.status === "answered";

  const submit = async () => {
    setBusy(true);
    try {
      await api.answerHumanRequest(scanId, req.request_id, { answer, solved });
      onDone && onDone();
    } finally {
      setBusy(false);
    }
  };

  const ctx = req.context || {};
  return (
    <div style={{
      border: "1px solid var(--border, #262a33)", borderRadius: 8, padding: 12,
      marginBottom: 10, background: "var(--bg-2, #14161c)",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
        <span style={{
          fontSize: 10, fontWeight: 700, color: "#0b0c10",
          background: answered ? "var(--green, #3fb950)" : "var(--orange, #d29922)",
          borderRadius: 4, padding: "2px 6px",
        }}>{answered ? "ANSWERED" : (req.kind || "assist").toUpperCase()}</span>
        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{req.created_at ? fmtDate(req.created_at) : ""}</span>
      </div>
      <div style={{ fontSize: 13, color: "var(--text-h)", marginTop: 6, wordBreak: "break-word" }}>{req.prompt}</div>
      {(ctx.category || ctx.reason) && (
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2, fontFamily: "var(--mono)" }}>
          {ctx.category ? `[${ctx.category}] ` : ""}{ctx.reason || ""}
        </div>
      )}
      <textarea
        value={answer} onChange={(e) => setAnswer(e.target.value)}
        placeholder="Your answer / evidence / steps taken…"
        rows={2}
        style={{
          width: "100%", marginTop: 8, background: "var(--bg, #0d0f13)",
          color: "var(--text-h)", border: "1px solid var(--border, #262a33)",
          borderRadius: 6, padding: 8, fontSize: 12, fontFamily: "var(--mono)", resize: "vertical",
        }}
      />
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8 }}>
        <label style={{ fontSize: 12, color: "var(--text-dim)", display: "flex", alignItems: "center", gap: 6 }}>
          <input type="checkbox" checked={solved} onChange={(e) => setSolved(e.target.checked)} />
          Mark solved (counts as confirmed)
        </label>
        <button className="btn btn-primary btn-sm" disabled={busy} onClick={submit}>
          {busy ? "Saving…" : (answered ? "Update" : "Submit")}
        </button>
      </div>
    </div>
  );
}

export default function HumanAssistPanel({ scanId, poll = false }) {
  const [requests, setRequests] = useState([]);
  const [pending, setPending] = useState(0);

  const load = async () => {
    try {
      const r = await api.getHumanRequests(scanId);
      setRequests(r.requests || []);
      setPending(r.pending || 0);
    } catch { /* ignore */ }
  };

  useEffect(() => {
    load();
    let iv = null;
    if (poll) iv = setInterval(load, 3000);
    return () => { if (iv) clearInterval(iv); };
  }, [scanId, poll]);

  const pend = requests.filter(r => r.status === "pending");
  const done = requests.filter(r => r.status !== "pending");

  return (
    <div className="card" style={{ margin: 0 }}>
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-h)" }}>
          Human Assist {pending ? `(${pending} pending)` : ""}
        </div>
        <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
          Tasks the scanner offloaded to you (non-DAST puzzles, OSINT, business logic, CAPTCHA).
          Answer & mark solved — solved items count in the benchmark score.
        </div>
      </div>

      {requests.length === 0 ? (
        <div style={{ padding: 20, textAlign: "center", color: "var(--text-dim)", fontSize: 13 }}>
          No human-assist requests. Enable with NEO_HUMAN_ASSIST=1; the scanner will post
          challenges it can't solve alone here.
        </div>
      ) : (
        <>
          {pend.map(r => <RequestCard key={r.request_id} scanId={scanId} req={r} onDone={load} />)}
          {done.length > 0 && (
            <div style={{ fontSize: 12, color: "var(--text-dim)", margin: "10px 0 6px" }}>Answered</div>
          )}
          {done.map(r => <RequestCard key={r.request_id} scanId={scanId} req={r} onDone={load} />)}
        </>
      )}
    </div>
  );
}
