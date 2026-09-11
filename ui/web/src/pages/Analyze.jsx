import { useState } from "react";
import { api } from "../api";

// Individual (standalone) analysis — analyze an APK/IPA or source tree on its
// own, with no target and no full scan.
export default function Analyze() {
  return (
    <div>
      <h1>Analyze</h1>
      <p style={{ color: "var(--text-dim)", fontSize: 13, marginTop: -8 }}>
        Individual testing — inspect a mobile app binary or a source checkout on its own,
        without launching a scan against a live target.
      </p>
      <div className="two-col" style={{ marginTop: 12, alignItems: "start" }}>
        <MobileAnalyze />
        <SourceAnalyze />
      </div>
    </div>
  );
}

function MobileAnalyze() {
  const [upload, setUpload] = useState(null);   // {path, kind, filename}
  const [uploading, setUploading] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const onFile = async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    setUploading(true); setError(""); setResult(null);
    try { setUpload(await api.uploadScanInput(file)); }
    catch (err) { setError(err.message || "Upload failed"); }
    finally { setUploading(false); }
  };

  const run = async () => {
    if (!upload) return;
    setRunning(true); setError("");
    try { setResult(await api.analyzeMobile(upload.path)); }
    catch (err) { setError(err.message || "Analysis failed"); }
    finally { setRunning(false); }
  };

  return (
    <div className="card" style={{ margin: 0 }}>
      <h3>Mobile app (.apk / .ipa)</h3>
      <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 10 }}>
        Extracts backend endpoints, hardcoded secrets, deeplinks and cert-pinning / ATS config.
        APK decompile needs apktool/jadx on the server.
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
        <input type="file" accept=".apk,.ipa" onChange={onFile} disabled={uploading || running}
          style={{ fontSize: 12, color: "var(--text)" }} />
        {uploading && <span style={{ fontSize: 12, color: "var(--text-dim)" }}>Uploading…</span>}
        {upload && !uploading && <span style={{ fontSize: 12, color: "var(--green)" }}>✓ {upload.filename}</span>}
      </div>
      <button className="btn btn-primary btn-sm" onClick={run} disabled={!upload || running}>
        {running ? "Analyzing…" : "Analyze"}
      </button>
      {error && <div className="error-msg" style={{ marginTop: 10 }}>{error}</div>}
      {result && (
        <div style={{ marginTop: 12 }}>
          <div className="card-grid">
            <Stat label="Endpoints" value={result.endpoint_count} />
            <Stat label="Secrets" value={result.secret_count} color="var(--red)" />
            <Stat label="Deeplinks" value={result.deeplink_count} />
            <Stat label="Cert Pinning" value={result.cert_pinning ? "yes" : "no"} />
          </div>
          <ListBlock title="Backend endpoints" items={result.endpoints} mono />
          <ListBlock title="Secrets" color="var(--red)"
            items={(result.secrets || []).map((s) => `${s.type}: ${s.match}`)} mono />
          <ListBlock title="Deeplinks" items={result.deeplinks} mono />
        </div>
      )}
    </div>
  );
}

function SourceAnalyze() {
  const [repo, setRepo] = useState("");
  const [path, setPath] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const run = async () => {
    if (!repo.trim() && !path.trim()) { setError("Enter a repo URL or a source path."); return; }
    setRunning(true); setError(""); setResult(null);
    try { setResult(await api.analyzeSource(repo.trim(), path.trim())); }
    catch (err) { setError(err.message || "SAST failed"); }
    finally { setRunning(false); }
  };

  const inputStyle = { padding: "6px 10px", borderRadius: 6, border: "1px solid var(--border)",
    background: "var(--bg-card)", color: "var(--text)", fontSize: 12, width: "100%" };

  return (
    <div className="card" style={{ margin: 0 }}>
      <h3>Source code (grey-box SAST)</h3>
      <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 10 }}>
        Runs Semgrep security rules and groups findings by class. Needs semgrep on the server
        (git too, for a repo URL).
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 10 }}>
        <input type="url" placeholder="Source repo URL (https://github.com/org/repo)"
          value={repo} onChange={(e) => setRepo(e.target.value)} style={inputStyle} />
        <input type="text" placeholder="…or a source path on the server (/path/to/repo)"
          value={path} onChange={(e) => setPath(e.target.value)} style={inputStyle} />
      </div>
      <button className="btn btn-primary btn-sm" onClick={run} disabled={running}>
        {running ? "Running SAST…" : "Run SAST"}
      </button>
      {error && <div className="error-msg" style={{ marginTop: 10 }}>{error}</div>}
      {result && (
        <div style={{ marginTop: 12 }}>
          <div className="card-grid">
            <Stat label="Findings" value={result.finding_count} color={result.finding_count ? "var(--orange)" : undefined} />
          </div>
          {Object.keys(result.by_class || {}).length > 0 && (
            <div className="pill-row" style={{ marginTop: 8 }}>
              {Object.entries(result.by_class).map(([k, n]) => <span key={k} className="pill">{k}: {n}</span>)}
            </div>
          )}
          <div className="table-wrap" style={{ marginTop: 10 }}>
            <table>
              <thead><tr><th>Class</th><th>Severity</th><th>File</th></tr></thead>
              <tbody>
                {(result.findings || []).slice(0, 200).map((f, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: 12 }}>{f.vuln_class}</td>
                    <td><span className={`badge ${(f.severity || "info").toLowerCase()}`}>{(f.severity || "").toUpperCase()}</span></td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{f.file}:{f.line}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {result.finding_count === 0 && (
            <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>
              No findings (or Semgrep/git not installed on the server).
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div className="stat-card">
      <span className="label">{label}</span>
      <span className="value" style={{ fontSize: 20, color }}>{value}</span>
    </div>
  );
}

function ListBlock({ title, items, color, mono }) {
  if (!items || items.length === 0) return null;
  return (
    <div style={{ marginTop: 10 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: color || "var(--text-dim)", marginBottom: 4 }}>
        {title} ({items.length})
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 200, overflow: "auto",
                    fontFamily: mono ? "var(--mono)" : undefined, fontSize: 11, color: "var(--text)" }}>
        {items.slice(0, 200).map((x, i) => <div key={i}>{x}</div>)}
      </div>
    </div>
  );
}
