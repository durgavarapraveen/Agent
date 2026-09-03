import { useEffect, useState, useCallback } from "react";
import { api } from "../api";

export default function ReviewQueue() {
  const [tab, setTab] = useState("manual");
  const [summary, setSummary] = useState({ success: 0, needs_manual: 0, total: 0 });
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const all = await api.getReviewQueue();
      setSummary(all.summary || {});
      const rows = tab === "success"
        ? (await api.getReviewSuccesses()).items
        : (await api.getReviewManual()).items;
      setItems(rows || []);
    } catch {
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [tab]);

  useEffect(() => { load(); }, [load]);

  const resolve = async (id) => {
    const note = window.prompt("Resolution note (optional):", "") || "";
    try {
      await api.resolveReview(id, note);
      await load();
    } catch (e) { /* ignore */ }
  };

  return (
    <div>
      <h1>Agent Review Queue</h1>
      <p style={{ color: "var(--muted)", marginTop: -8 }}>
        Confirmed exploits to verify &amp; showcase, and objectives the agent couldn't crack —
        handed to you with what it tried and suggested next steps.
      </p>

      <div className="card-grid" style={{ marginBottom: 24 }}>
        <div className="stat-card">
          <span className="label">Confirmed Exploits</span>
          <span className="value" style={{ color: "var(--green)" }}>{summary.success || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">Needs Manual Pentest</span>
          <span className="value" style={{ color: "var(--amber, #e0a500)" }}>{summary.needs_manual || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">Total Attempts</span>
          <span className="value">{summary.total || 0}</span>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button className={`badge ${tab === "manual" ? "scope-violation" : ""}`}
          style={tabBtn(tab === "manual")} onClick={() => setTab("manual")}>
          Needs Attention ({summary.needs_manual || 0})
        </button>
        <button className={`badge ${tab === "success" ? "scope-ok" : ""}`}
          style={tabBtn(tab === "success")} onClick={() => setTab("success")}>
          Confirmed Exploits ({summary.success || 0})
        </button>
        <button style={tabBtn(false)} onClick={load}>Refresh</button>
      </div>

      {loading ? (
        <div className="loading">Loading...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          {tab === "success" ? "No confirmed exploits yet." : "Nothing waiting for manual review."}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {items.map((r) => (
            <div key={r.id} className="stat-card" style={{ alignItems: "stretch", textAlign: "left" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
                <div>
                  <span className={`badge ${tab === "success" ? "scope-ok" : "scope-violation"}`}>
                    {tab === "success" ? "EXPLOITED" : "MANUAL"}
                  </span>
                  {r.severity ? <span className={`badge ${String(r.severity).toLowerCase()}`} style={{ marginLeft: 6 }}>{r.severity}</span> : null}
                  <strong style={{ marginLeft: 8 }}>{r.title}</strong>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button style={tabBtn(false)} onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                    {expanded === r.id ? "Hide" : "Details"}
                  </button>
                  {tab === "manual" && (
                    <button style={{ ...tabBtn(false), color: "var(--green)" }} onClick={() => resolve(r.id)}>
                      Mark handled
                    </button>
                  )}
                </div>
              </div>
              <div style={{ color: "var(--muted)", fontSize: 12, marginTop: 6 }}>
                <span style={{ fontFamily: "var(--mono)" }}>{r.target}</span>
                {r.category ? <> &middot; {r.category}</> : null}
                {r.steps ? <> &middot; {r.steps} steps</> : null}
                {r.created_at ? <> &middot; {fmtTs(r.created_at)}</> : null}
              </div>

              {tab === "manual" && r.manual_guidance && (
                <div style={guidanceBox}>
                  <strong style={{ color: "var(--amber, #e0a500)" }}>Suggested next steps:</strong>
                  <div style={{ marginTop: 4 }}>{r.manual_guidance}</div>
                </div>
              )}
              {tab === "success" && r.evidence && (
                <div style={{ ...guidanceBox, borderColor: "var(--green)" }}>
                  <strong style={{ color: "var(--green)" }}>Evidence:</strong>
                  <div style={{ marginTop: 4, fontFamily: "var(--mono)", fontSize: 12 }}>{r.evidence}</div>
                </div>
              )}

              {expanded === r.id && (
                <div style={{ marginTop: 10 }}>
                  {r.tried_summary && (
                    <div style={{ fontSize: 12, marginBottom: 8 }}>
                      <strong>What the agent tried:</strong>
                      <div style={{ fontFamily: "var(--mono)", color: "var(--muted)", marginTop: 4 }}>{r.tried_summary}</div>
                    </div>
                  )}
                  {Array.isArray(r.history) && r.history.length > 0 && (
                    <details>
                      <summary style={{ cursor: "pointer", fontSize: 12 }}>Action history ({r.history.length})</summary>
                      <pre style={preBox}>{JSON.stringify(r.history, null, 2)}</pre>
                    </details>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const tabBtn = (active) => ({
  cursor: "pointer",
  border: "1px solid var(--border, #333)",
  background: active ? "var(--surface-2, #1c1c22)" : "transparent",
  color: "inherit",
  padding: "6px 12px",
  borderRadius: 6,
  fontSize: 13,
});

const guidanceBox = {
  marginTop: 10,
  padding: "8px 12px",
  borderLeft: "3px solid var(--amber, #e0a500)",
  background: "var(--surface-2, rgba(255,255,255,0.03))",
  borderRadius: 4,
  fontSize: 13,
};

const preBox = {
  background: "var(--surface-2, #0e0e12)",
  padding: 10,
  borderRadius: 6,
  fontSize: 11,
  maxHeight: 300,
  overflow: "auto",
  marginTop: 6,
};

function fmtTs(ts) {
  if (!ts) return "";
  try {
    const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
    return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return String(ts); }
}
