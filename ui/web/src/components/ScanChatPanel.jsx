import { useState, useRef, useEffect } from "react";
import { api } from "../api";

/**
 * Scan-scoped chatbot. Sends messages to /api/scans/{id}/chat which pulls
 * fresh scan context from the DB every call, so answers reflect the latest
 * scan state even mid-scan.
 */
const SUGGESTED = [
  "Summarize the most critical findings",
  "Which credentials were exfiltrated and how?",
  "List every SQL injection endpoint with proof",
  "Which subdomains have security misconfig?",
  "How did we gain admin access?",
  "What technologies did we fingerprint?",
  "Which authentication endpoints are exposed?",
  "Show all OSINT-discovered employees",
];

export default function ScanChatPanel({ scanId }) {
  const [msgs, setMsgs] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [stats, setStats] = useState(null);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, busy]);

  const send = async (text) => {
    const t = (text ?? input).trim();
    if (!t || busy) return;
    setInput("");
    const nextMsgs = [...msgs, { role: "user", content: t }];
    setMsgs(nextMsgs);
    setBusy(true);
    try {
      const r = await api.askScanChat(scanId, t, nextMsgs.slice(0, -1));
      setMsgs([...nextMsgs, { role: "assistant", content: r.answer || "(no answer)" }]);
      if (r.context_stats) setStats(r.context_stats);
    } catch (e) {
      setMsgs([...nextMsgs, { role: "assistant", content: `Error: ${e.message || e}` }]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 260px)", minHeight: 400 }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10, padding: "8px 12px",
        border: "1px solid var(--border)", borderRadius: 6, marginBottom: 10,
        background: "var(--bg-elev)",
      }}>
        <span style={{ fontSize: 18 }}>◆</span>
        <span style={{ fontWeight: 700, letterSpacing: 1, color: "var(--accent, #00ff9a)" }}>
          ASK ABOUT THIS SCAN
        </span>
        {stats && (
          <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
            reusing {stats.phase_summaries || 0} scan-time summaries · {stats.vulns} vulns · {stats.access} access
          </span>
        )}
      </div>

      {/* Suggestions when empty */}
      {msgs.length === 0 && (
        <div style={{
          border: "1px dashed var(--border)", borderRadius: 6,
          padding: 16, marginBottom: 10, color: "var(--text-dim)",
        }}>
          <div style={{ marginBottom: 10, fontSize: 12 }}>
            Ask anything about the vulnerabilities, access gained, credentials, OSINT, or recon
            data for this scan. Try one of these:
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {SUGGESTED.map((s) => (
              <button key={s} className="btn btn-sm" onClick={() => send(s)}
                style={{ fontSize: 12, borderColor: "var(--border)" }}>
                {s}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Messages */}
      <div style={{
        flex: 1, overflowY: "auto", border: "1px solid var(--border)",
        borderRadius: 6, padding: 12, background: "var(--bg)",
      }}>
        {msgs.map((m, i) => <ChatBubble key={i} role={m.role} content={m.content} />)}
        {busy && (
          <div style={{ padding: 12, color: "var(--text-dim)", fontStyle: "italic" }}>
            <span style={{ animation: "pulse 1s infinite" }}>…</span> thinking
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={(e) => { e.preventDefault(); send(); }}
        style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <input
          type="text" value={input} onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about the scan…"
          disabled={busy}
          style={{
            flex: 1, padding: "10px 12px", borderRadius: 6,
            border: "1px solid var(--border)", background: "var(--bg-elev)",
            color: "var(--text-h)", fontFamily: "var(--mono)", fontSize: 13,
            outline: "none",
          }}
        />
        <button type="submit" disabled={busy || !input.trim()} className="btn"
          style={{
            background: busy ? "var(--text-dim)" : "var(--accent, #00ff9a)",
            color: "#000", fontWeight: 700, padding: "0 16px",
            border: 0, borderRadius: 6, cursor: busy ? "wait" : "pointer",
          }}>
          {busy ? "…" : "Send"}
        </button>
      </form>
    </div>
  );
}

function ChatBubble({ role, content }) {
  const isUser = role === "user";
  return (
    <div style={{
      display: "flex", justifyContent: isUser ? "flex-end" : "flex-start",
      marginBottom: 12,
    }}>
      <div style={{
        maxWidth: "82%",
        background: isUser ? "var(--bg-elev)" : "rgba(0,255,154,0.06)",
        border: `1px solid ${isUser ? "var(--border)" : "var(--accent, #00ff9a)"}`,
        borderRadius: 8, padding: "10px 12px",
      }}>
        <div style={{
          fontSize: 10, letterSpacing: 1, fontWeight: 700,
          color: isUser ? "var(--text-dim)" : "var(--accent, #00ff9a)",
          marginBottom: 4, textTransform: "uppercase",
        }}>
          {isUser ? "You" : "Analyst"}
        </div>
        <pre style={{
          margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word",
          fontFamily: isUser ? "var(--mono)" : "inherit", fontSize: 13,
          color: "var(--text-h)", lineHeight: 1.5,
        }}>{content}</pre>
      </div>
    </div>
  );
}
