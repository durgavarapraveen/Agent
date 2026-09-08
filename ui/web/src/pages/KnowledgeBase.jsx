import { useState, useEffect, useRef } from "react";
import { api } from "../api";

const TABS = ["Documents", "Upload", "URL", "Search", "Notes", "Query"];

// Small inline progress bar used while an ingestion job runs.
function ProgressBar({ percent, label }) {
  const pct = Math.max(0, Math.min(100, Math.round(percent || 0)));
  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--text-m)", marginBottom: 6 }}>
        <span>{label || "Ingesting…"}</span>
        <span>{pct}%</span>
      </div>
      <div style={{ height: 8, borderRadius: 999, background: "var(--border)", overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${pct}%`, background: "var(--accent)", transition: "width 0.3s ease" }} />
      </div>
    </div>
  );
}

// Generate a client-side job id and poll ingestion progress until terminal.
function newJobId() {
  try { return crypto.randomUUID(); }
  catch { return "job_" + Math.random().toString(36).slice(2) + Date.now().toString(36); }
}

async function pollIngestProgress(jobId, onTick, { intervalMs = 700, stopRef } = {}) {
  // Returns the final progress record ({status, percent, result, error}).
  while (true) {
    if (stopRef?.current) return null;
    let p;
    try { p = await api.ragIngestProgress(jobId); }
    catch { p = null; }
    if (p) {
      onTick?.(p);
      if (p.status === "done" || p.status === "error") return p;
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
}
const SOURCE_LABELS = {
  seed: "Built-in Security Knowledge",
  file: "Uploaded Files",
  url: "Web Pages",
  text: "Manual Notes",
  web_search: "Web Search Results",
  scan_finding: "Scan Findings",
};

export default function KnowledgeBase() {
  const [tab, setTab] = useState("Documents");
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [initLoading, setInitLoading] = useState(false);
  const [msg, setMsg] = useState(null);

  const loadStats = () => {
    api.ragStats()
      .then(setStats)
      .catch(() => setStats(null))
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadStats(); }, []);

  const handleInit = async () => {
    setInitLoading(true);
    try {
      const r = await api.ragInit();
      setMsg({ type: "ok", text: `Initialized: ${r.total_documents || 0} documents` });
      loadStats();
    } catch (e) {
      setMsg({ type: "err", text: e.message });
    }
    setInitLoading(false);
  };

  const flash = (type, text) => {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 6000);
  };

  const notReady = !stats || stats.error;

  return (
    <div>
      <div className="page-header">
        <h1>Knowledge Base (RAG)</h1>
        <p style={{ color: "var(--text-m)", marginTop: 4, fontSize: 13 }}>
          Upload files, URLs, and notes to make DeepSeek smarter about cybersecurity
        </p>
      </div>

      {msg && (
        <div style={{
          padding: "10px 16px", borderRadius: "var(--radius-sm)", marginBottom: 16,
          background: msg.type === "ok" ? "var(--green-bg, #0d2818)" : "var(--red-bg, #2d1215)",
          color: msg.type === "ok" ? "var(--green, #4ade80)" : "var(--red, #f87171)",
          border: `1px solid ${msg.type === "ok" ? "var(--green, #4ade80)" : "var(--red, #f87171)"}33`,
          fontSize: 13,
        }}>
          {msg.text}
        </div>
      )}

      {notReady && !loading && (
        <div className="card" style={{ textAlign: "center", padding: 40 }}>
          <h3 style={{ marginBottom: 12 }}>RAG Pipeline Not Initialized</h3>
          <p style={{ color: "var(--text-m)", marginBottom: 20, fontSize: 13 }}>
            Initialize to seed the cybersecurity knowledge base and enable RAG-augmented scanning.
          </p>
          <button className="btn btn-primary" onClick={handleInit} disabled={initLoading}>
            {initLoading ? "Initializing..." : "Initialize RAG Pipeline"}
          </button>
        </div>
      )}

      {!notReady && (
        <>
          <StatsCards stats={stats} />

          <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
            {TABS.map(t => (
              <button key={t} onClick={() => setTab(t)}
                style={{
                  padding: "8px 18px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
                  background: tab === t ? "var(--accent)" : "var(--card)", color: tab === t ? "#fff" : "var(--text-h)",
                  cursor: "pointer", fontSize: 13, fontWeight: tab === t ? 600 : 400,
                }}>
                {t}
              </button>
            ))}
          </div>

          {tab === "Documents" && <DocumentsTab flash={flash} reload={loadStats} />}
          {tab === "Upload" && <UploadTab flash={flash} reload={loadStats} />}
          {tab === "URL" && <URLTab flash={flash} reload={loadStats} />}
          {tab === "Search" && <SearchTab flash={flash} reload={loadStats} />}
          {tab === "Notes" && <NotesTab flash={flash} reload={loadStats} />}
          {tab === "Query" && <QueryTab />}

          <SourceBreakdown stats={stats} reload={loadStats} flash={flash} />
        </>
      )}
    </div>
  );
}

function StatsCards({ stats }) {
  if (!stats) return null;
  const sources = stats.by_source || {};
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 20 }}>
      <StatCard label="Total Documents" value={stats.total_documents || 0} color="var(--accent)" />
      <StatCard label="Uploaded Files" value={sources.file || 0} color="#3b82f6" />
      <StatCard label="Web Pages" value={sources.url || 0} color="#8b5cf6" />
      <StatCard label="Web Searches" value={sources.web_search || 0} color="#f59e0b" />
      <StatCard label="Manual Notes" value={sources.text || 0} color="#10b981" />
      <StatCard label="Scan Findings" value={sources.scan_finding || 0} color="#ef4444" />
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="card" style={{ padding: "14px 16px" }}>
      <div style={{ fontSize: 24, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 12, color: "var(--text-m)", marginTop: 2 }}>{label}</div>
    </div>
  );
}

function DocumentsTab({ flash, reload }) {
  const [docs, setDocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState({});
  const [deleting, setDeleting] = useState(null);

  const loadDocs = (sourceType) => {
    setLoading(true);
    api.ragListDocuments(sourceType || undefined, 200, 0)
      .then(r => setDocs(r.documents || []))
      .catch(() => setDocs([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadDocs(filter); }, [filter]);

  const toggle = (id) => setExpanded(p => ({ ...p, [id]: !p[id] }));

  const handleDelete = async (docId) => {
    setDeleting(docId);
    try {
      await api.ragDeleteDoc(docId);
      setDocs(d => d.filter(x => x.doc_id !== docId));
      flash("ok", "Document deleted");
      reload();
    } catch (e) { flash("err", e.message); }
    setDeleting(null);
  };

  const sourceColors = {
    seed: "#6366f1", file: "#3b82f6", url: "#8b5cf6",
    text: "#10b981", web_search: "#f59e0b", scan_finding: "#ef4444",
  };

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h3 style={{ margin: 0 }}>All Documents ({docs.length})</h3>
        <select value={filter} onChange={e => setFilter(e.target.value)}
          style={{
            padding: "6px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
            background: "var(--bg)", color: "var(--text-h)", fontSize: 12,
          }}>
          <option value="">All Sources</option>
          {Object.entries(SOURCE_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
      </div>

      {loading && <div style={{ color: "var(--text-m)", fontSize: 13, padding: 20, textAlign: "center" }}>Loading documents...</div>}

      {!loading && docs.length === 0 && (
        <div style={{ color: "var(--text-m)", fontSize: 13, padding: 20, textAlign: "center" }}>No documents found</div>
      )}

      {!loading && docs.map(doc => (
        <div key={doc.doc_id} style={{
          border: "1px solid var(--border)", borderRadius: "var(--radius-sm)",
          marginBottom: 8, overflow: "hidden",
        }}>
          <div
            onClick={() => toggle(doc.doc_id)}
            style={{
              padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
              background: expanded[doc.doc_id] ? "var(--bg)" : "transparent",
            }}>
            <span style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-d)", minWidth: 16 }}>
              {expanded[doc.doc_id] ? "▼" : "▶"}
            </span>
            <span style={{
              padding: "2px 8px", borderRadius: 10, fontSize: 10, fontWeight: 600,
              background: (sourceColors[doc.source_type] || "#666") + "22",
              color: sourceColors[doc.source_type] || "#999",
              whiteSpace: "nowrap",
            }}>
              {doc.source_type}
            </span>
            <span style={{ fontSize: 13, color: "var(--text-h)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {doc.metadata?.title || doc.metadata?.filename || doc.metadata?.url || doc.source_ref || doc.doc_id}
            </span>
            <span style={{ fontSize: 11, color: "var(--text-d)", whiteSpace: "nowrap" }}>
              {doc.content_length ? `${(doc.content_length / 1024).toFixed(1)}KB` : ""}
            </span>
            <button
              onClick={e => { e.stopPropagation(); handleDelete(doc.doc_id); }}
              disabled={deleting === doc.doc_id}
              style={{
                padding: "3px 8px", borderRadius: "var(--radius-sm)",
                border: "1px solid #f8717133", background: "transparent",
                color: "#f87171", fontSize: 10, cursor: "pointer",
              }}>
              {deleting === doc.doc_id ? "..." : "×"}
            </button>
          </div>

          {expanded[doc.doc_id] && (
            <div style={{ padding: "0 14px 14px 40px", borderTop: "1px solid var(--border)" }}>
              {doc.metadata && Object.keys(doc.metadata).length > 0 && (
                <div style={{ marginTop: 10, marginBottom: 8 }}>
                  <div style={{ fontSize: 11, color: "var(--accent)", fontWeight: 600, marginBottom: 4 }}>Metadata</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {Object.entries(doc.metadata).map(([k, v]) => (
                      <span key={k} style={{
                        padding: "2px 8px", borderRadius: 10, fontSize: 10,
                        background: "var(--accent)15", color: "var(--text-m)",
                        border: "1px solid var(--accent)20",
                      }}>
                        <strong>{k}:</strong> {typeof v === "string" ? v : JSON.stringify(v)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ marginTop: 8 }}>
                <div style={{ fontSize: 11, color: "var(--accent)", fontWeight: 600, marginBottom: 4 }}>Content</div>
                <pre style={{
                  fontSize: 12, color: "var(--text-m)", whiteSpace: "pre-wrap", wordBreak: "break-word",
                  maxHeight: 300, overflow: "auto", padding: 10, borderRadius: "var(--radius-sm)",
                  background: "var(--bg)", border: "1px solid var(--border)", margin: 0,
                  fontFamily: "monospace",
                }}>
                  {doc.content}
                </pre>
              </div>
              <div style={{ fontSize: 10, color: "var(--text-d)", marginTop: 8 }}>
                ID: {doc.doc_id} | Source: {doc.source_ref} | Created: {doc.created_at ? new Date(doc.created_at).toLocaleString() : "unknown"}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function UploadTab({ flash, reload }) {
  const fileRef = useRef();
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [progress, setProgress] = useState(null); // {percent, label}

  const handleFiles = async (files) => {
    if (!files?.length) return;
    setUploading(true);
    for (const file of files) {
      const jobId = newJobId();
      setProgress({ percent: 0, label: `${file.name} — starting…` });
      try {
        const started = await api.ragUploadFile(file, {}, jobId);
        if (started && started.status === "started") {
          const final = await pollIngestProgress(jobId, (p) =>
            setProgress({ percent: p.percent, label: `${file.name} — ${p.done}/${p.total} chunks` }));
          if (final?.status === "error") {
            flash("err", `${file.name}: ${final.error || "ingestion failed"}`);
          } else {
            const nc = final?.result?.new_chunks ?? 0;
            flash("ok", `${file.name}: ${nc} new chunks ingested`);
          }
        } else {
          // Backend without job support — synchronous result.
          flash("ok", `${file.name}: ${started.new_chunks} new chunks ingested`);
        }
      } catch (e) {
        flash("err", `${file.name}: ${e.message}`);
      }
    }
    setProgress(null);
    setUploading(false);
    reload();
  };

  return (
    <div className="card">
      <h3>Upload Files</h3>
      <p style={{ color: "var(--text-m)", fontSize: 13, marginBottom: 16 }}>
        Supports PDF, TXT, Markdown, HTML, CSV, JSON, YAML. Drag & drop or click to browse.
      </p>
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => { e.preventDefault(); setDragOver(false); handleFiles(e.dataTransfer.files); }}
        onClick={() => fileRef.current?.click()}
        style={{
          border: `2px dashed ${dragOver ? "var(--accent)" : "var(--border)"}`,
          borderRadius: "var(--radius)", padding: 40, textAlign: "center",
          cursor: "pointer", background: dragOver ? "var(--accent)11" : "transparent",
          transition: "all 0.2s",
        }}>
        <div style={{ fontSize: 32, marginBottom: 8 }}>+</div>
        <div style={{ color: "var(--text-m)", fontSize: 13 }}>
          {uploading ? "Uploading..." : "Drop files here or click to browse"}
        </div>
      </div>
      {progress && <ProgressBar percent={progress.percent} label={progress.label} />}
      <input ref={fileRef} type="file" multiple hidden accept=".pdf,.txt,.md,.html,.htm,.csv,.json,.yaml,.yml,.rst,.log"
        onChange={e => handleFiles(e.target.files)} />
    </div>
  );
}

function URLTab({ flash, reload }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    const jobId = newJobId();
    setProgress({ percent: 0, label: "Fetching page…" });
    try {
      const started = await api.ragIngestUrl(url.trim(), {}, jobId);
      if (started && started.status === "started") {
        const final = await pollIngestProgress(jobId, (p) =>
          setProgress({ percent: p.percent, label: `${p.done}/${p.total} chunks` }));
        if (final?.status === "error") {
          flash("err", final.error || "ingestion failed");
        } else {
          flash("ok", `URL ingested: ${final?.result?.new_chunks ?? 0} new chunks`);
          setUrl("");
        }
      } else {
        flash("ok", `URL ingested: ${started.new_chunks} new chunks`);
        setUrl("");
      }
      reload();
    } catch (e) {
      flash("err", e.message);
    }
    setProgress(null);
    setLoading(false);
  };

  return (
    <div className="card">
      <h3>Add Web Page</h3>
      <p style={{ color: "var(--text-m)", fontSize: 13, marginBottom: 16 }}>
        Paste a URL to fetch and ingest its content. Works with documentation pages, blog posts, OWASP pages, etc.
      </p>
      <form onSubmit={handleSubmit} style={{ display: "flex", gap: 8 }}>
        <input type="url" value={url} onChange={e => setUrl(e.target.value)}
          placeholder="https://owasp.org/www-community/attacks/SQL_Injection"
          style={{
            flex: 1, padding: "9px 14px", borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13,
          }} />
        <button className="btn btn-primary" type="submit" disabled={loading || !url.trim()}>
          {loading ? "Fetching..." : "Ingest URL"}
        </button>
      </form>
      {progress && <ProgressBar percent={progress.percent} label={progress.label} />}
    </div>
  );
}

function SearchTab({ flash, reload }) {
  const [query, setQuery] = useState("");
  const [maxResults, setMaxResults] = useState(3);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [progress, setProgress] = useState(null);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    const jobId = newJobId();
    setProgress({ percent: 0, label: "Searching the web…" });
    try {
      const started = await api.ragSearch(query.trim(), maxResults, jobId);
      if (started && started.status === "started") {
        const final = await pollIngestProgress(jobId, (p) =>
          setProgress({ percent: p.percent, label: `step ${p.done}/${p.total}` }));
        if (final?.status === "error") {
          flash("err", final.error || "search failed");
        } else {
          const r = final?.result || {};
          setResult(r);
          flash("ok", `Search complete: ${r.new_chunks ?? 0} new chunks from ${r.pages_fetched ?? 0} pages`);
        }
      } else {
        setResult(started);
        flash("ok", `Search complete: ${started.new_chunks} new chunks from ${started.pages_fetched} pages`);
      }
      reload();
    } catch (e) {
      flash("err", e.message);
    }
    setProgress(null);
    setLoading(false);
  };

  return (
    <div className="card">
      <h3>Web Search & Ingest</h3>
      <p style={{ color: "var(--text-m)", fontSize: 13, marginBottom: 16 }}>
        Search the web for cybersecurity knowledge. Results are automatically fetched and ingested.
      </p>
      <form onSubmit={handleSearch} style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input type="text" value={query} onChange={e => setQuery(e.target.value)}
          placeholder="SSRF bypass techniques 2024"
          style={{
            flex: 1, padding: "9px 14px", borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13,
          }} />
        <select value={maxResults} onChange={e => setMaxResults(+e.target.value)}
          style={{
            padding: "9px 14px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
            background: "var(--bg)", color: "var(--text-h)", fontSize: 13, width: 80,
          }}>
          <option value={3}>3</option>
          <option value={5}>5</option>
          <option value={10}>10</option>
        </select>
        <button className="btn btn-primary" type="submit" disabled={loading || !query.trim()}>
          {loading ? "Searching..." : "Search & Ingest"}
        </button>
      </form>
      {progress && <ProgressBar percent={progress.percent} label={progress.label} />}
      {result && result.sources && (
        <div style={{ fontSize: 12, color: "var(--text-m)" }}>
          <strong>Sources ingested:</strong>
          <ul style={{ margin: "6px 0", paddingLeft: 20 }}>
            {result.sources.map((s, i) => (
              <li key={i}><a href={s} target="_blank" rel="noopener" style={{ color: "var(--accent)" }}>{s}</a></li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function NotesTab({ flash, reload }) {
  const [text, setText] = useState("");
  const [title, setTitle] = useState("");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!text.trim()) return;
    setLoading(true);
    const jobId = newJobId();
    setProgress({ percent: 0, label: "Saving note…" });
    try {
      const started = await api.ragIngestText(text.trim(), title.trim() || "manual_note", {}, jobId);
      if (started && started.status === "started") {
        const final = await pollIngestProgress(jobId, (p) =>
          setProgress({ percent: p.percent, label: `${p.done}/${p.total} chunks` }));
        if (final?.status === "error") {
          flash("err", final.error || "ingestion failed");
        } else {
          flash("ok", `Note ingested: ${final?.result?.new_chunks ?? 0} new chunks`);
          setText("");
          setTitle("");
        }
      } else {
        flash("ok", `Note ingested: ${started.new_chunks} new chunks`);
        setText("");
        setTitle("");
      }
      reload();
    } catch (e) {
      flash("err", e.message);
    }
    setProgress(null);
    setLoading(false);
  };

  return (
    <div className="card">
      <h3>Add Notes</h3>
      <p style={{ color: "var(--text-m)", fontSize: 13, marginBottom: 16 }}>
        Paste your own security notes, payloads, techniques, or findings.
      </p>
      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <input type="text" value={title} onChange={e => setTitle(e.target.value)}
          placeholder="Title (e.g. Custom SQLi bypass for WAF X)"
          style={{
            padding: "9px 14px", borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13,
          }} />
        <textarea value={text} onChange={e => setText(e.target.value)}
          placeholder="Paste your security notes, payloads, or findings here..."
          rows={8}
          style={{
            padding: "9px 14px", borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)",
            fontSize: 13, resize: "vertical", fontFamily: "monospace",
          }} />
        <button className="btn btn-primary" type="submit" disabled={loading || !text.trim()} style={{ alignSelf: "flex-start" }}>
          {loading ? "Saving..." : "Add to Knowledge Base"}
        </button>
      </form>
      {progress && <ProgressBar percent={progress.percent} label={progress.label} />}
    </div>
  );
}

function QueryTab() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleQuery = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    try {
      const r = await api.ragQuery(query.trim(), 10);
      setResults(r.results || []);
    } catch { setResults([]); }
    setLoading(false);
  };

  return (
    <div className="card">
      <h3>Query Knowledge Base</h3>
      <p style={{ color: "var(--text-m)", fontSize: 13, marginBottom: 16 }}>
        Test what the RAG retrieves for a given query. This is what DeepSeek sees before each API call.
      </p>
      <form onSubmit={handleQuery} style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <input type="text" value={query} onChange={e => setQuery(e.target.value)}
          placeholder="SQL injection login bypass"
          style={{
            flex: 1, padding: "9px 14px", borderRadius: "var(--radius-sm)",
            border: "1px solid var(--border)", background: "var(--bg)", color: "var(--text-h)", fontSize: 13,
          }} />
        <button className="btn btn-primary" type="submit" disabled={loading || !query.trim()}>
          {loading ? "Searching..." : "Query"}
        </button>
      </form>
      {results && (
        <div>
          <div style={{ fontSize: 12, color: "var(--text-m)", marginBottom: 10 }}>
            {results.length} results found
          </div>
          {results.map((doc, i) => (
            <div key={i} style={{
              padding: 12, borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
              marginBottom: 8, background: "var(--bg)",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ fontSize: 12, color: "var(--accent)", fontWeight: 600 }}>
                  {doc.metadata?.title || doc.metadata?.filename || doc.metadata?.url || "Document"}
                </span>
                <span style={{
                  fontSize: 11, padding: "2px 8px", borderRadius: 10,
                  background: doc.similarity > 0.7 ? "#16a34a22" : doc.similarity > 0.4 ? "#f59e0b22" : "#6b728022",
                  color: doc.similarity > 0.7 ? "#4ade80" : doc.similarity > 0.4 ? "#fbbf24" : "var(--text-m)",
                }}>
                  {(doc.similarity * 100).toFixed(0)}% match
                </span>
              </div>
              <div style={{ fontSize: 12, color: "var(--text-m)", whiteSpace: "pre-wrap", maxHeight: 120, overflow: "auto" }}>
                {doc.content}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-d)", marginTop: 6 }}>
                Source: {doc.metadata?.category || "unknown"} | {doc.doc_id}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SourceBreakdown({ stats, reload, flash }) {
  const [deleting, setDeleting] = useState(null);

  if (!stats?.by_source) return null;
  const sources = Object.entries(stats.by_source).filter(([, v]) => v > 0);
  if (!sources.length) return null;

  const handleDelete = async (sourceType) => {
    if (sourceType === "seed") return;
    setDeleting(sourceType);
    try {
      const r = await api.ragDelete(sourceType);
      flash("ok", `Deleted ${r.deleted} documents from ${SOURCE_LABELS[sourceType] || sourceType}`);
      reload();
    } catch (e) {
      flash("err", e.message);
    }
    setDeleting(null);
  };

  return (
    <div className="card" style={{ marginTop: 20 }}>
      <h3>Source Breakdown</h3>
      <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 12, fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid var(--border)" }}>
            <th style={{ textAlign: "left", padding: "8px 12px", color: "var(--text-m)", fontWeight: 500 }}>Source</th>
            <th style={{ textAlign: "right", padding: "8px 12px", color: "var(--text-m)", fontWeight: 500 }}>Documents</th>
            <th style={{ textAlign: "right", padding: "8px 12px", color: "var(--text-m)", fontWeight: 500 }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {sources.map(([src, count]) => (
            <tr key={src} style={{ borderBottom: "1px solid var(--border)" }}>
              <td style={{ padding: "8px 12px", color: "var(--text-h)" }}>{SOURCE_LABELS[src] || src}</td>
              <td style={{ padding: "8px 12px", textAlign: "right", color: "var(--text-h)" }}>{count}</td>
              <td style={{ padding: "8px 12px", textAlign: "right" }}>
                {src !== "seed" && (
                  <button onClick={() => handleDelete(src)} disabled={deleting === src}
                    style={{
                      padding: "4px 10px", borderRadius: "var(--radius-sm)",
                      border: "1px solid var(--red, #f87171)44", background: "transparent",
                      color: "var(--red, #f87171)", fontSize: 11, cursor: "pointer",
                    }}>
                    {deleting === src ? "..." : "Clear All"}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {stats.by_category && Object.keys(stats.by_category).length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 12, color: "var(--text-m)", marginBottom: 8 }}>Categories:</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {Object.entries(stats.by_category).map(([cat, count]) => (
              <span key={cat} style={{
                padding: "3px 10px", borderRadius: 10, fontSize: 11,
                background: "var(--accent)22", color: "var(--accent)",
                border: "1px solid var(--accent)33",
              }}>
                {cat} ({count})
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
