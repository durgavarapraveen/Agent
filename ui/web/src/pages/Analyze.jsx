import { useState, useEffect } from "react";
import { api } from "../api";

// Strip the server-side clone/extract temp prefix so the file reads as a
// repo-relative path (…\sast_repo_xxxx\a\b.py -> a/b.py).
function relPath(p) {
  if (!p) return "";
  const s = String(p).replace(/\\/g, "/");
  const m = s.match(/(?:sast_repo_[^/]+|code_[^/]+|gbox_[^/]+|repo_[^/]+)\/(.+)$/);
  return m ? m[1] : s;
}

// Dataflow evidence for a taint finding: untrusted input → dangerous sink.
// This is the "yes, it's actually reachable in this code" proof.
function TaintLine({ taint }) {
  if (!taint || (!taint.source && !taint.sink)) return null;
  const L = (n) => (n && n.line ? `L${n.line}` : "?");
  return (
    <div style={{ marginTop: 4, fontSize: 11, fontFamily: "var(--mono)", color: "var(--text-dim)" }}>
      <span style={{ color: "var(--orange)" }}>input {L(taint.source)}</span>
      {" → "}
      <span style={{ color: "var(--red)" }}>sink {L(taint.sink)}</span>
      {taint.source?.content && (
        <div style={{ color: "var(--text-mute)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 380 }}>
          {taint.source.content}
        </div>
      )}
    </div>
  );
}

// Shared SAST findings table — one source of truth for the (previously 3x
// duplicated) Severity / Issue / Class / File layout, with taint evidence.
function SastTable({ rows, limit = 150 }) {
  const list = rows || [];
  if (!list.length) return null;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Severity</th><th>Issue</th><th>Class</th><th>File</th></tr></thead>
        <tbody>
          {list.slice(0, limit).map((f, i) => (
            <tr key={i}>
              <td><span className={`badge ${(f.severity || "info").toLowerCase()}`}>{(f.severity || "").toUpperCase()}</span></td>
              <td style={{ fontSize: 12, maxWidth: 420 }}>
                <div style={{ color: "var(--text-h)" }}>{f.title || f.check_id || f.vuln_class}</div>
                {f.check_id && <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-mute)" }}>{f.check_id}</div>}
                <TaintLine taint={f.taint} />
              </td>
              <td style={{ fontSize: 12 }}>{f.vuln_class}</td>
              <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{relPath(f.file)}:{f.line}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Skeleton bar — a single shimmering placeholder line.
function Sk({ w = "100%", h = 12, r = 6, style }) {
  return <span className="skeleton" style={{ display: "block", width: w, height: h, borderRadius: r, ...style }} />;
}

// Result-shaped skeleton shown while a grey-box job is running.
function GreyboxResultSkeleton() {
  return (
    <div style={{ marginTop: 12 }}>
      <div className="card-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        {[0, 1, 2].map((i) => (
          <div key={i} className="card" style={{ margin: 0, padding: 12 }}>
            <Sk w="50%" h={10} />
            <Sk w="35%" h={22} style={{ marginTop: 10 }} />
          </div>
        ))}
      </div>
      <div className="table-wrap" style={{ marginTop: 12 }}>
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} style={{ display: "flex", gap: 12, padding: "10px 12px" }}>
            <Sk w={70} h={14} r={999} />
            <Sk w="45%" h={14} />
            <Sk w="20%" h={14} style={{ marginLeft: "auto" }} />
          </div>
        ))}
      </div>
    </div>
  );
}

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
      <div style={{
        marginTop: 8, marginBottom: 4, padding: "8px 12px", borderRadius: 8,
        background: "var(--bg-surface)", border: "1px solid var(--border)",
        fontSize: 12, color: "var(--text-dim)", display: "flex", gap: 8, alignItems: "center",
      }}>
        <span aria-hidden="true">ℹ️</span>
        <span>Results appear in <b>Recent Analyses</b> below — not in <b>Scan History</b>
          (that tab lists live-target scans started from <b>Live Scans</b>).</span>
      </div>
      <div className="two-col" style={{ marginTop: 12, alignItems: "start" }}>
        <MobileAnalyze />
        <SourceAnalyze />
      </div>
      <RecentAnalyses />
    </div>
  );
}

function RecentAnalyses() {
  const [rows, setRows] = useState([]);
  const [open, setOpen] = useState(null);   // full stored analysis
  const [loading, setLoading] = useState(false);
  const [firstLoad, setFirstLoad] = useState(true);

  const refresh = () => api.listAnalyses(100)
    .then((d) => setRows(d.analyses || []))
    .finally(() => setFirstLoad(false));
  useEffect(() => { refresh(); const t = setInterval(refresh, 15000); return () => clearInterval(t); }, []);

  const view = async (id) => {
    setLoading(true);
    try { setOpen(await api.getAnalysis(id)); } catch { /* ignore */ } finally { setLoading(false); }
  };

  const fmt = (ts) => { try { return new Date(ts).toLocaleString(); } catch { return ts; } };
  const summaryText = (a) => {
    const s = a.summary || {};
    if (a.kind === "greybox") return `SAST ${s.sast_count ?? 0} · DAST ${s.dast_count ?? 0} · confirmed ${(s.correlation || {}).confirmed ?? 0}`;
    if (a.kind === "mobile") return `endpoints ${s.endpoint_count ?? 0} · secrets ${s.secret_count ?? 0}`;
    return `findings ${s.finding_count ?? 0}`;
  };

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="flex-between" style={{ alignItems: "baseline" }}>
        <h3 style={{ margin: 0 }}>Recent Analyses</h3>
        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{rows.length} stored</span>
      </div>
      {firstLoad ? (
        <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 10 }}>
          {[0, 1, 2].map((i) => (
            <div key={i} style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <Sk w={64} h={16} r={999} />
              <Sk w="30%" h={12} />
              <Sk w="25%" h={12} />
              <Sk w={90} h={12} style={{ marginLeft: "auto" }} />
            </div>
          ))}
        </div>
      ) : rows.length === 0 ? (
        <div className="empty" style={{ marginTop: 8 }}>No stored analyses yet. Run one above.</div>
      ) : (
        <div className="table-wrap" style={{ border: "none", boxShadow: "none", marginTop: 8 }}>
          <table>
            <thead><tr><th>Kind</th><th>Source</th><th>Summary</th><th>When</th><th></th></tr></thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className="click-row" onClick={() => view(a.id)}>
                  <td><span className="badge">{(a.kind || "").toUpperCase()}</span></td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 11, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.source}</td>
                  <td style={{ fontSize: 12, color: "var(--text-dim)" }}>{summaryText(a)}</td>
                  <td style={{ fontSize: 11, whiteSpace: "nowrap" }}>{fmt(a.created_at)}</td>
                  <td><button className="btn btn-ghost btn-sm">View</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {loading && <div style={{ marginTop: 10, color: "var(--text-dim)", fontSize: 12 }}>Loading…</div>}
      {open && (
        <div style={{ marginTop: 14, borderTop: "1px solid var(--border)", paddingTop: 12 }}>
          <div className="flex-between" style={{ alignItems: "baseline" }}>
            <h3 style={{ margin: 0 }}>{(open.kind || "").toUpperCase()} — {open.source}</h3>
            <button className="btn btn-ghost btn-sm" onClick={() => setOpen(null)}>Close</button>
          </div>
          {open.result?.correlation
            ? <GreyboxResult result={open.result} />
            : <StoredGenericResult result={open.result} kind={open.kind} />}
        </div>
      )}
    </div>
  );
}

function StoredGenericResult({ result, kind }) {
  if (!result) return null;
  if (kind === "mobile") {
    return (
      <div style={{ marginTop: 10 }}>
        <div className="card-grid">
          <Stat label="Endpoints" value={result.endpoint_count} />
          <Stat label="Secrets" value={result.secret_count} color="var(--red)" />
          <Stat label="Deeplinks" value={result.deeplink_count} />
        </div>
        <ListBlock title="Backend endpoints" items={result.endpoints} mono />
      </div>
    );
  }
  // SAST
  return (
    <div style={{ marginTop: 10 }}>
      <div className="card-grid"><Stat label="Findings" value={result.finding_count} color={result.finding_count ? "var(--orange)" : undefined} /></div>
      <SastTable rows={result.findings} limit={200} />
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

function GreyboxProgress({ steps, running }) {
  const dot = (status) => {
    if (status === "done") return { bg: "var(--green)", ch: "✓", fg: "#fff" };
    if (status === "error") return { bg: "var(--red)", ch: "!", fg: "#fff" };
    return { bg: "var(--accent)", ch: "", fg: "#fff" };
  };
  // The last step is "current" while the job is still running.
  const lastIdx = steps.length - 1;
  return (
    <div style={{
      marginTop: 12, padding: 14, borderRadius: 10,
      background: "var(--bg-surface)", border: "1px solid var(--border)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1,
          textTransform: "uppercase", color: "var(--text-dim)" }}>Grey-box progress</span>
        {running && <span className="spinner" style={{
          width: 12, height: 12, border: "2px solid var(--border)",
          borderTopColor: "var(--accent)", borderRadius: "50%",
          display: "inline-block", animation: "spin 0.8s linear infinite" }} />}
      </div>
      {steps.length === 0 && (
        <div style={{ fontSize: 12, color: "var(--text-dim)" }}>Starting…</div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
        {steps.map((s, i) => {
          const isCurrent = running && i === lastIdx && s.status === "running";
          const d = dot(isCurrent ? "running" : s.status);
          const isLast = i === lastIdx;
          return (
            <div key={i} style={{ display: "flex", gap: 10, position: "relative" }}>
              {/* rail */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                <span style={{
                  width: 18, height: 18, borderRadius: "50%", flexShrink: 0,
                  background: d.bg, color: d.fg, fontSize: 11, fontWeight: 700,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  boxShadow: isCurrent ? "0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent)" : "none",
                }}>
                  {isCurrent
                    ? <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#fff",
                        animation: "pulse 1s ease-in-out infinite" }} />
                    : d.ch}
                </span>
                {!isLast && <span style={{ width: 2, flex: 1, minHeight: 14,
                  background: "var(--border)" }} />}
              </div>
              {/* label */}
              <div style={{ paddingBottom: isLast ? 0 : 12, flex: 1 }}>
                <div style={{ fontSize: 13,
                  color: s.status === "error" ? "var(--red)" : "var(--text)",
                  fontWeight: isCurrent ? 600 : 400 }}>{s.msg}</div>
                {s.ts && <div style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 2 }}>
                  {new Date(s.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                </div>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SourceAnalyze() {
  const [repo, setRepo] = useState("");
  const [zipFile, setZipFile] = useState(null);
  const [greybox, setGreybox] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [steps, setSteps] = useState([]);

  const onZip = (e) => {
    const f = e.target.files && e.target.files[0];
    setZipFile(f || null);
    if (f) setRepo("");        // one source at a time
    setError(""); setResult(null);
  };

  const run = async () => {
    if (!zipFile && !repo.trim()) { setError("Upload a .zip of your codebase or enter a GitHub repo URL."); return; }
    setRunning(true); setError(""); setResult(null); setSteps([]);
    try {
      if (greybox) {
        // Grey-box is a background job — start it, then poll live steps.
        const { job_id } = zipFile ? await api.analyzeGreyboxZip(zipFile)
                                   : await api.analyzeGreybox(repo.trim(), "");
        if (!job_id) throw new Error("could not start grey-box job");
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
        // Poll until the job finishes (or ~30 min safety cap).
        for (let i = 0; i < 1200; i++) {
          await sleep(1500);
          let p;
          try { p = await api.getGreyboxProgress(job_id); }
          catch (e) {
            // 404 = job gone (server restarted / expired) — stop, don't spin.
            if (e && e.status === 404) {
              setError("Grey-box job not found — the server was restarted or the job expired. Please run it again.");
              break;
            }
            continue;   // transient network hiccup — keep polling
          }
          setSteps(p.steps || []);
          if (p.status === "completed") { setResult(p.result); break; }
          if (p.status === "failed") { setError(p.error || "grey-box analysis failed"); break; }
        }
      } else {
        setResult(zipFile ? await api.analyzeSourceZip(zipFile)
                          : await api.analyzeSource(repo.trim(), ""));
      }
    } catch (err) { setError(err.message || "Analysis failed"); }
    finally { setRunning(false); }
  };

  const inputStyle = { padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)",
    background: "var(--bg-card)", color: "var(--text)", fontSize: 13, width: "100%" };

  return (
    <div className="card" style={{ margin: 0 }}>
      <h3>Source code (grey-box SAST)</h3>
      <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 10 }}>
        Upload a .zip of your codebase or point at a GitHub repo. Runs Semgrep security rules
        and groups findings by vulnerability class. Needs semgrep on the server (git too, for a repo URL).
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 8 }}>
        <label style={{ fontSize: 11, fontWeight: 600, color: "var(--text-dim)" }}>Upload codebase (.zip)</label>
        <input type="file" accept=".zip" onChange={onZip} disabled={running}
          style={{ fontSize: 12, color: "var(--text)" }} />
        {zipFile && <span style={{ fontSize: 12, color: "var(--green)" }}>✓ {zipFile.name}</span>}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "6px 0" }}>
        <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
        <span style={{ fontSize: 11, color: "var(--text-mute)" }}>OR</span>
        <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
        <label style={{ fontSize: 11, fontWeight: 600, color: "var(--text-dim)" }}>GitHub repo URL</label>
        <input type="url" placeholder="https://github.com/org/repo"
          value={repo} onChange={(e) => { setRepo(e.target.value); if (e.target.value) setZipFile(null); }}
          disabled={running} style={inputStyle} />
      </div>

      <label style={{ display: "flex", gap: 8, alignItems: "flex-start", margin: "4px 0 12px", fontSize: 12, cursor: "pointer" }}>
        <input type="checkbox" checked={greybox} onChange={(e) => setGreybox(e.target.checked)} disabled={running}
          style={{ marginTop: 2 }} />
        <span style={{ color: "var(--text)" }}>
          <b>Grey-box</b> — also build &amp; run the app and DAST it, then correlate with SAST
          <span style={{ display: "block", color: "var(--text-dim)", fontSize: 11 }}>
            Needs a Dockerfile / docker-compose in the codebase. Slower (build + run + scan).
          </span>
        </span>
      </label>
      <button className="btn btn-primary btn-sm" onClick={run} disabled={running}>
        {running ? (greybox ? "Running grey-box…" : "Running SAST…") : (greybox ? "Run Grey-box" : "Run SAST")}
      </button>
      {(steps.length > 0 || (running && greybox)) && (
        <GreyboxProgress steps={steps} running={running} />
      )}
      {running && greybox && !result && <GreyboxResultSkeleton />}
      {error && <div className="error-msg" style={{ marginTop: 10 }}>{error}</div>}
      {result && result.correlation && <GreyboxResult result={result} />}
      {result && !result.correlation && (
        <div style={{ marginTop: 12 }}>
          <div className="card-grid">
            <Stat label="Findings" value={result.finding_count} color={result.finding_count ? "var(--orange)" : undefined} />
          </div>
          {Object.keys(result.by_class || {}).length > 0 && (
            <div className="pill-row" style={{ marginTop: 8 }}>
              {Object.entries(result.by_class).map(([k, n]) => <span key={k} className="pill">{k}: {n}</span>)}
            </div>
          )}
          <SastTable rows={result.findings} limit={200} />
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

function GreyboxResult({ result }) {
  const c = result.correlation || {};
  const counts = c.counts || {};
  const confirmed = c.confirmed || [];
  return (
    <div style={{ marginTop: 12 }}>
      <div className="card-grid">
        <Stat label="SAST findings" value={result.sast_count} color={result.sast_count ? "var(--orange)" : undefined} />
        <Stat label="DAST findings" value={result.dast_count} color={result.dast_count ? "var(--red)" : undefined} />
        <Stat label="Confirmed (both)" value={counts.confirmed || 0} color={counts.confirmed ? "var(--green)" : undefined} />
      </div>

      <div style={{ marginTop: 8, fontSize: 12, color: result.dynamic_ran ? "var(--green)" : "var(--text-dim)" }}>
        {result.dynamic_ran
          ? `● Dynamic DAST ran against ${result.dynamic_url}`
          : `○ Dynamic DAST skipped — ${result.dynamic_reason || "not run"} (SAST-only)`}
      </div>

      <div className="pill-row" style={{ marginTop: 10 }}>
        <span className="pill" style={{ color: "var(--green)" }}>Confirmed {counts.confirmed || 0}</span>
        <span className="pill" style={{ color: "var(--orange)" }}>SAST-only {counts.sast_only || 0}</span>
        <span className="pill" style={{ color: "var(--blue)" }}>DAST-only {counts.dast_only || 0}</span>
      </div>

      {confirmed.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--green)", marginBottom: 6 }}>
            Confirmed by SAST + DAST ({confirmed.length}) — highest confidence
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Class</th><th>Severity</th><th>Source (SAST)</th><th>Runtime (DAST)</th></tr></thead>
              <tbody>
                {confirmed.slice(0, 100).map((f, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: 12 }}>{f.vuln_class}</td>
                    <td><span className={`badge ${(f.severity || "info").toLowerCase()}`}>{(f.severity || "").toUpperCase()}</span></td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{f.sast?.file}:{f.sast?.line}</td>
                    <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{f.dast?.target || f.dast?.location || f.dast?.url || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(result.sast || []).length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-dim)", marginBottom: 6 }}>
            All SAST findings ({result.sast.length})
          </div>
          <SastTable rows={result.sast} limit={150} />
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
