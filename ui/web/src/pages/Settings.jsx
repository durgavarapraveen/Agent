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

  // LLM provider (Claude CLI / Amazon Bedrock / DeepSeek).
  const [provider, setProvider] = useState("claude_cli");
  const [providerMsg, setProviderMsg] = useState("");
  // DeepSeek API key (only relevant when provider = deepseek).
  const [dsKeyDraft, setDsKeyDraft] = useState("");
  const [dsConfigured, setDsConfigured] = useState(false);
  const [dsReveal, setDsReveal] = useState(false);
  const [dsMsg, setDsMsg] = useState("");
  // Metasploit auxiliary scanners (read-only network verification).
  const [msfEnabled, setMsfEnabled] = useState(false);
  const [msfMsg, setMsfMsg] = useState("");
  const [modelRoles, setModelRoles] = useState(null);
  useEffect(() => {
    api.getLlmProvider().then(r => setProvider(r.provider || "claude_cli")).catch(() => {});
    api.getDeepseekKey().then(r => setDsConfigured(!!r.configured)).catch(() => {});
    api.getMetasploit().then(r => setMsfEnabled(!!r.enabled)).catch(() => {});
    api.getModelRoles().then(setModelRoles).catch(() => {});
  }, []);
  const saveProvider = (p) => {
    setProvider(p);
    setProviderMsg("Saving…");
    api.setLlmProvider(p)
      .then(r => setProviderMsg(`Saved. ${r.note || "Applies to the next scan."}`))
      .catch(() => setProviderMsg("Failed to save."));
  };
  const saveDsKey = () => {
    setDsMsg("Saving…");
    api.setDeepseekKey(dsKeyDraft.trim())
      .then(r => { setDsConfigured(!!r.configured); setDsKeyDraft("");
                   setDsMsg(r.configured ? "Saved. Applies to the next scan." : "Cleared."); })
      .catch(() => setDsMsg("Failed to save."));
  };
  const toggleMsf = () => {
    const next = !msfEnabled;
    setMsfEnabled(next);
    setMsfMsg("Saving…");
    api.setMetasploit(next)
      .then(r => { setMsfEnabled(!!r.enabled); setMsfMsg(r.note || "Saved."); })
      .catch(() => { setMsfEnabled(!next); setMsfMsg("Failed to save."); });
  };

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
        <h3>LLM Provider</h3>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 12 }}>
          Which backend powers reasoning &amp; payload generation. Applies to the next scan you start.
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <select value={provider} onChange={(e) => saveProvider(e.target.value)}
            style={{ padding: "9px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13, width: 240 }}>
            <option value="claude_cli">Claude CLI (Max/Pro subscription)</option>
            <option value="bedrock">Amazon Bedrock</option>
            <option value="deepseek">DeepSeek (API key)</option>
          </select>
          <span style={{
            fontSize: 11, fontFamily: "var(--mono)", padding: "3px 9px", borderRadius: 6,
            border: "1px solid var(--border)", color: "var(--text-h)",
            background: "var(--accent-dim, rgba(0,113,227,0.10))",
          }}>active: {provider}</span>
        </div>
        {providerMsg && (
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-dim)" }}>{providerMsg}</div>
        )}
        {provider === "bedrock" && (
          <div style={{ marginTop: 8, fontSize: 12, color: "var(--orange)" }}>
            Ensure your Bedrock model access is activated, or scans will produce no findings.
          </div>
        )}
        {provider === "deepseek" && (
          <div style={{ marginTop: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ color: "var(--text-dim)", fontWeight: 600, minWidth: 100, fontSize: 13 }}>DeepSeek API Key</span>
              <input
                type={dsReveal ? "text" : "password"}
                value={dsKeyDraft}
                onChange={(e) => { setDsKeyDraft(e.target.value); setDsMsg(""); }}
                placeholder={dsConfigured ? "•••••••• (a key is saved — paste to replace)" : "sk-… paste your DeepSeek API key"}
                style={{
                  fontFamily: "var(--mono)", fontSize: 12, padding: "6px 10px",
                  borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
                  background: "var(--bg)", color: "var(--text-h)", minWidth: 320, flex: 1,
                }}
              />
              <button className="btn" onClick={() => setDsReveal(v => !v)} style={{ fontSize: 12 }}>
                {dsReveal ? "Hide" : "Show"}
              </button>
              <button className="btn btn-primary" disabled={!dsKeyDraft.trim()} onClick={saveDsKey} style={{ fontSize: 12 }}>
                Save Key
              </button>
              {dsConfigured && (
                <button className="btn" onClick={() => { setDsKeyDraft(""); api.setDeepseekKey("").then(() => { setDsConfigured(false); setDsMsg("Cleared."); }); }} style={{ fontSize: 12 }}>
                  Clear
                </button>
              )}
            </div>
            <div style={{ marginTop: 6, fontSize: 12, color: dsConfigured ? "var(--green)" : "var(--orange)" }}>
              {dsMsg || (dsConfigured ? "✓ A DeepSeek key is saved." : "No DeepSeek key set — scans will fail until you add one.")}
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h3>LLM Models &amp; Cost</h3>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 12 }}>
          Which Bedrock model handles each task role, whether it is accessible, and the per-1M
          rate. Read-only — configure with the <code>AWS_BEDROCK_&lt;ROLE&gt;_MODEL</code>,
          <code> AWS_BEDROCK_ALLOWED_MODELS</code> and <code>LLM_PRICING_JSON</code> env vars.
        </p>
        {!modelRoles && <div style={{ color: "var(--text-dim)", fontSize: 13 }}>Loading…</div>}
        {modelRoles && (
          <>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10, flexWrap: "wrap" }}>
              <span className={`badge ${modelRoles.zdr?.zdr_required ? "info" : "low"}`}>
                {modelRoles.zdr?.zdr_required ? "ZDR ON" : "ZDR OFF"}
              </span>
              {modelRoles.zdr?.zdr_required && (
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                  data_retention=“{modelRoles.zdr.data_retention || "none"}” · prompt/response content not stored
                </span>
              )}
              {modelRoles.allowlist?.length > 0 && (
                <span style={{ fontSize: 11, color: "var(--text-dim)" }}>· allowlist: {modelRoles.allowlist.join(", ")}</span>
              )}
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Role</th><th>Model</th><th>Source</th><th>Access</th><th style={{ textAlign: "right" }}>Rate $/1M (in/out)</th></tr>
                </thead>
                <tbody>
                  {(modelRoles.roles || []).map((r) => {
                    const rate = modelRoles.pricing?.[r.model];
                    return (
                      <tr key={r.role}>
                        <td style={{ color: "var(--text-h)", textTransform: "capitalize" }}>{r.role}</td>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{r.model || "—"}</td>
                        <td>
                          {r.downgraded ? (
                            <span className="badge critical" title={`Configured "${r.wanted}" not accessible — using "${r.model}". Add it to AWS_BEDROCK_ALLOWED_MODELS.`}>downgraded</span>
                          ) : (
                            <span className={`badge ${r.source === "configured" ? "info" : r.source === "auto" ? "medium" : "low"}`}
                              title={r.source === "auto" ? "Auto-selected by capability from accessible models" : r.source === "configured" ? "Set via AWS_BEDROCK_<ROLE>_MODEL" : "Default small/large model"}>
                              {r.source || (r.configured ? "configured" : "fallback")}
                            </span>
                          )}
                        </td>
                        <td><span className={`badge ${r.accessible ? "info" : "critical"}`}>{r.accessible ? "accessible" : "blocked"}</span></td>
                        <td style={{ textAlign: "right", fontFamily: "var(--mono)", fontSize: 12 }}>
                          {rate ? (rate.known ? `$${rate.input_per_1m} / $${rate.output_per_1m}` : "no price") : "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      <div className="card">
        <h3>Metasploit (network verification)</h3>
        <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 12 }}>
          Runs <strong>read-only</strong> Metasploit <code>auxiliary/scanner</code> modules against open
          network services (SMB, RDP, SSH, FTP, SMTP, HTTP) found during recon. No exploit or payload
          modules run. Authorized targets only. Applies to the next scan you start.
        </p>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <button className={msfEnabled ? "btn btn-primary" : "btn"} onClick={toggleMsf} style={{ fontSize: 13 }}>
            {msfEnabled ? "Enabled — click to disable" : "Disabled — click to enable"}
          </button>
          <span style={{
            fontSize: 11, fontFamily: "var(--mono)", padding: "3px 9px", borderRadius: 6,
            border: "1px solid var(--border)", color: "var(--text-h)",
            background: msfEnabled ? "rgba(48,209,88,0.12)" : "var(--accent-dim, rgba(0,113,227,0.10))",
          }}>NEO_ENABLE_MSF: {msfEnabled ? "1" : "0"}</span>
        </div>
        {msfMsg && (
          <div style={{ marginTop: 10, fontSize: 12, color: "var(--text-dim)" }}>{msfMsg}</div>
        )}
        <div style={{ marginTop: 8, fontSize: 12, color: "var(--orange)" }}>
          Requires the msfconsole binary in the Kali container. Results appear as agent cards in Parallel
          Agents, raw output in Tool Outputs, and any VULNERABLE hit as a finding.
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
          <div><span style={{ color: "var(--text)", fontWeight: 600 }}>Neo</span> v2.0 Autonomous Security Testing Engine</div>
          <div>Coverage Matrix: 43 test types across 858+ cells</div>
          <div>Powered by multi-LLM reasoning with DeepSeek + Claude</div>
        </div>
      </div>
    </div>
  );
}
