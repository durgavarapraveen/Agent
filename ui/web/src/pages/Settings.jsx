import { useState, useEffect } from "react";
import { api, getApiKey, setApiKey, clearApiKey } from "../api";

export default function Settings() {
  const [saved, setSaved] = useState(false);
  const [killing, setKilling] = useState(false);
  const [killResult, setKillResult] = useState(null);
  const [apiStatus, setApiStatus] = useState("checking");
  const [defaults, setDefaults] = useState(() => {
    try { return JSON.parse(localStorage.getItem("ag_defaults") || "{}"); }
    catch { return {}; }
  });

  // API key management. Masked for display; explicit "reveal" via button.
  const [apiKeyDraft, setApiKeyDraft] = useState(() => getApiKey());
  const [revealKey, setRevealKey] = useState(false);
  const [keySavedMsg, setKeySavedMsg] = useState("");

  const update = (key, val) => {
    setDefaults(prev => {
      const next = { ...prev, [key]: val };
      localStorage.setItem("ag_defaults", JSON.stringify(next));
      return next;
    });
    setSaved(false);
  };

  useEffect(() => {
    api.getScans()
      .then(() => setApiStatus("connected"))
      .catch(() => setApiStatus("error"));
  }, []);

  const save = () => {
    localStorage.setItem("ag_defaults", JSON.stringify(defaults));
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div>
      <div className="page-header">
        <h1>Settings</h1>
      </div>

      <div className="card">
        <h3>Scan Defaults</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 12 }}>
          <div className="form-group">
            <label>Default Tier</label>
            <select value={defaults.tier || "DEEP"} onChange={(e) => update("tier", e.target.value)}
              style={{ padding: "9px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13, width: 200 }}>
              <option value="POC">POC</option>
              <option value="SHALLOW">Shallow</option>
              <option value="DEEP">Deep</option>
            </select>
          </div>
          <label className="scan-option" style={{ maxWidth: 300 }}>
            <input type="checkbox" checked={defaults.auto_approve !== false} onChange={(e) => update("auto_approve", e.target.checked)} />
            Auto-approve exploits by default
          </label>
          <label className="scan-option" style={{ maxWidth: 300 }}>
            <input type="checkbox" checked={!!defaults.skip_osint} onChange={(e) => update("skip_osint", e.target.checked)} />
            Skip OSINT by default
          </label>
        </div>
        <div style={{ marginTop: 16 }}>
          <button className="btn btn-primary" onClick={save}>
            {saved ? "Saved" : "Save Defaults"}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>API Connection</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 12, fontSize: 13 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ color: "var(--text-dim)", fontWeight: 600, minWidth: 100 }}>Endpoint</span>
            <code style={{ fontFamily: "var(--mono)", color: "var(--accent)", fontSize: 12, padding: "4px 10px", background: "var(--bg)", borderRadius: "var(--radius-sm)" }}>
              {window.__ANTIGRAVITY_API__ || `${window.location.origin}`}
            </code>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ color: "var(--text-dim)", fontWeight: 600, minWidth: 100 }}>Status</span>
            <span style={{ display: "flex", alignItems: "center", gap: 6, color: apiStatus === "connected" ? "var(--green)" : apiStatus === "error" ? "var(--red)" : "var(--text-dim)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: apiStatus === "connected" ? "var(--green)" : apiStatus === "error" ? "var(--red)" : "var(--text-dim)", display: "inline-block" }} />
              {apiStatus === "connected" ? "Connected" : apiStatus === "error" ? "Disconnected" : "Checking..."}
            </span>
          </div>
          {/* ── API key management ───────────────────────────────────── */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ color: "var(--text-dim)", fontWeight: 600, minWidth: 100 }}>API Key</span>
            <input
              type={revealKey ? "text" : "password"}
              value={apiKeyDraft}
              onChange={(e) => { setApiKeyDraft(e.target.value); setKeySavedMsg(""); }}
              placeholder="Paste the key printed at the API's first boot"
              style={{
                fontFamily: "var(--mono)", fontSize: 12,
                padding: "6px 10px", borderRadius: "var(--radius-sm)",
                border: "1px solid var(--border)", background: "var(--bg)",
                color: "var(--text-h)", minWidth: 320, flex: 1,
              }}
            />
            <button
              className="btn"
              onClick={() => setRevealKey(v => !v)}
              style={{ fontSize: 12 }}
              title={revealKey ? "Hide" : "Show"}
            >
              {revealKey ? "Hide" : "Show"}
            </button>
            <button
              className="btn btn-primary"
              disabled={apiKeyDraft === getApiKey()}
              onClick={() => {
                setApiKey(apiKeyDraft.trim());
                setKeySavedMsg("Saved. Reloading validators…");
                // Trigger a lightweight probe so we surface success or 401.
                api.getScans()
                  .then(() => { setApiStatus("connected"); setKeySavedMsg("Saved. API responded ok."); })
                  .catch(() => { setApiStatus("error"); setKeySavedMsg("Saved, but the API rejected it."); });
              }}
              style={{ fontSize: 12 }}
            >
              Save Key
            </button>
            <button
              className="btn"
              disabled={!apiKeyDraft}
              onClick={() => {
                clearApiKey();
                setApiKeyDraft("");
                setKeySavedMsg("Cleared.");
              }}
              style={{ fontSize: 12 }}
            >
              Clear
            </button>
          </div>
          {keySavedMsg && (
            <div style={{ marginLeft: 108, color: "var(--text-dim)", fontSize: 12 }}>
              {keySavedMsg}
            </div>
          )}
          <div style={{ marginLeft: 108, color: "var(--text-dim)", fontSize: 11, lineHeight: 1.6 }}>
            The API prints an auto-generated dev key at first boot in the log. In production, set
            <code style={{ margin: "0 4px", fontFamily: "var(--mono)" }}>API_KEY</code>
            in the environment and paste it here.
          </div>
        </div>
      </div>

      <div className="card" style={{ borderColor: "var(--red, #e74c3c)" }}>
        <h3 style={{ color: "var(--red, #e74c3c)" }}>Emergency Kill Switch</h3>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 16 }}>
          Immediately terminate all running scan processes and mark them as cancelled.
          This cannot be undone.
        </p>
        <button
          className="btn"
          disabled={killing}
          onClick={() => {
            if (!window.confirm("Kill ALL running scans? This will terminate every active scan process immediately.")) return;
            setKilling(true);
            setKillResult(null);
            api.killAllScans()
              .then(r => setKillResult({ ok: true, count: r.count }))
              .catch(e => setKillResult({ ok: false, error: e.message }))
              .finally(() => setKilling(false));
          }}
          style={{
            background: "var(--red, #e74c3c)", color: "#fff", fontWeight: 700,
            padding: "10px 24px", border: "none", borderRadius: "var(--radius-sm)",
            cursor: killing ? "not-allowed" : "pointer", opacity: killing ? 0.6 : 1,
          }}
        >
          {killing ? "Killing..." : "Kill All Scans"}
        </button>
        {killResult && (
          <div style={{ marginTop: 12, fontSize: 13, color: killResult.ok ? "var(--green)" : "var(--red)" }}>
            {killResult.ok ? `Killed ${killResult.count} scan(s).` : `Error: ${killResult.error}`}
          </div>
        )}
      </div>

      <div className="card">
        <h3>About</h3>
        <div style={{ fontSize: 13, color: "var(--text-dim)", lineHeight: 1.8 }}>
          <div><span style={{ color: "var(--text)", fontWeight: 600 }}>AntiGravity</span> v2.0 Autonomous Security Testing Engine</div>
          <div>Coverage Matrix: 43 test types across 858+ cells</div>
          <div>Powered by multi-LLM reasoning with DeepSeek + Claude</div>
        </div>
      </div>
    </div>
  );
}
