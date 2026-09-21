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

const chatKey = (scanId) => `ag_scanchat_${scanId}`;
const loadChat = (scanId) => {
  try { return JSON.parse(localStorage.getItem(chatKey(scanId)) || "[]") || []; }
  catch { return []; }
};

export default function ScanChatPanel({ scanId }) {
  const [msgs, setMsgs] = useState(() => loadChat(scanId));
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [stats, setStats] = useState(null);
  const bottomRef = useRef(null);

  // Restore this scan's conversation on mount / when the scan changes, so
  // switching tabs (or reloading) never loses the chat history.
  useEffect(() => { setMsgs(loadChat(scanId)); setStats(null); }, [scanId]);

  // Persist per-scan on every change (per-viewer convenience; storage may be
  // unavailable in private windows, so guard it).
  useEffect(() => {
    try { localStorage.setItem(chatKey(scanId), JSON.stringify(msgs)); } catch { /* ignore */ }
  }, [msgs, scanId]);

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
          <span style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
            reusing {stats.phase_summaries || 0} scan-time summaries · {stats.vulns} vulns · {stats.access} access
          </span>
        )}
        {msgs.length > 0 && (
          <button onClick={() => { setMsgs([]); setStats(null); }}
            title="Clear this scan's conversation"
            style={{ marginLeft: "auto", fontSize: 11, padding: "3px 10px", borderRadius: 6,
                     border: "1px solid var(--border)", background: "var(--bg-card, #fff)",
                     color: "var(--text-dim)", cursor: "pointer" }}>
            Clear
          </button>
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
            background: busy ? "var(--text-dim)" : "var(--accent)",
            color: "var(--accent-on, #fff)", fontWeight: 700, padding: "0 16px",
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
        background: isUser ? "var(--bg-elev)" : "var(--accent-dim, #eef4ff)",
        border: `1px solid ${isUser ? "var(--border)" : "var(--accent)"}`,
        borderRadius: 8, padding: "10px 12px",
      }}>
        <div style={{
          fontSize: 10, letterSpacing: 1, fontWeight: 700,
          color: isUser ? "var(--text-dim)" : "var(--accent)",
          marginBottom: 4, textTransform: "uppercase",
        }}>
          {isUser ? "You" : "Analyst"}
        </div>
        {isUser ? (
          <pre style={{
            margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word",
            fontFamily: "var(--mono)", fontSize: 13, color: "var(--text-h)", lineHeight: 1.5,
          }}>{content}</pre>
        ) : (
          <Markdown text={content} />
        )}
      </div>
    </div>
  );
}

/* Tiny dependency-free markdown: **bold**, `code`, and -/1. lists. */
function renderInline(text) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**")) out.push(<strong key={out.length}>{tok.slice(2, -2)}</strong>);
    else out.push(
      <code key={out.length} style={{
        fontFamily: "var(--mono)", fontSize: 12, padding: "1px 5px", borderRadius: 4,
        background: "var(--bg-surface, #f5f5f7)", border: "1px solid var(--border)",
      }}>{tok.slice(1, -1)}</code>);
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function Markdown({ text }) {
  const lines = String(text || "").split("\n");
  const blocks = [];
  let list = null;
  const flush = () => { if (list) { blocks.push(list); list = null; } };
  lines.forEach((ln) => {
    const bullet = ln.match(/^\s*[-*]\s+(.*)/);
    const num = ln.match(/^\s*\d+\.\s+(.*)/);
    if (bullet || num) {
      const ordered = !!num;
      if (!list || list.ordered !== ordered) { flush(); list = { ordered, items: [] }; }
      list.items.push((bullet || num)[1]);
    } else {
      flush();
      blocks.push({ text: ln });
    }
  });
  flush();
  return (
    <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text)" }}>
      {blocks.map((b, i) => {
        if (b.items) {
          const Tag = b.ordered ? "ol" : "ul";
          return <Tag key={i} style={{ margin: "6px 0", paddingLeft: 20 }}>
            {b.items.map((it, j) => <li key={j} style={{ marginBottom: 3 }}>{renderInline(it)}</li>)}
          </Tag>;
        }
        if (!b.text.trim()) return <div key={i} style={{ height: 6 }} />;
        return <div key={i} style={{ marginBottom: 4 }}>{renderInline(b.text)}</div>;
      })}
    </div>
  );
}
