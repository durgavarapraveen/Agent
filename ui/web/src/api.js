// ─────────────────────────────────────────────────────────────────────────
// AntiGravity API client
//
// Auth: every HTTP request sends `X-API-Key: <key>` when a key is configured.
// The key is read from (in order):
//   1. `window.__ANTIGRAVITY_API_KEY__`  — injected by an operator at build/deploy
//   2. `localStorage["ag_api_key"]`      — set by the Settings page in-browser
//   3. `?api_key=…` in the current URL   — one-time bootstrap; auto-migrated to
//                                          localStorage and stripped from the URL
//
// WebSocket handshake carries the same key via the subprotocol pair
// `["api-key", "<key>"]`, matching the backend at `ui/api/server.py:ws_scan_feed`.
//
// 401 handling: because the whole app previously used `.catch(() => {})` to
// silence errors, unauthorized responses vanished silently and users saw blank
// tables. We now dispatch a `CustomEvent("ag:unauthorized", { detail })` so a
// top-level listener in `App.jsx` can surface a "session invalid" banner. Local
// handlers can still catch and ignore individual failures; unauthorized events
// are always broadcast in addition.
// ─────────────────────────────────────────────────────────────────────────

const BASE = window.__ANTIGRAVITY_API__ || "";

const API_KEY_STORAGE = "ag_api_key";

function _initApiKey() {
  // Priority 1: build-time global.
  if (typeof window !== "undefined" && window.__ANTIGRAVITY_API_KEY__) {
    return String(window.__ANTIGRAVITY_API_KEY__);
  }
  // Priority 3: bootstrap from `?api_key=…` if present, then persist + strip.
  try {
    const params = new URLSearchParams(window.location.search);
    const fromUrl = params.get("api_key");
    if (fromUrl) {
      localStorage.setItem(API_KEY_STORAGE, fromUrl);
      params.delete("api_key");
      const cleanQs = params.toString();
      const cleanUrl = window.location.pathname + (cleanQs ? "?" + cleanQs : "") + window.location.hash;
      window.history.replaceState({}, "", cleanUrl);
      return fromUrl;
    }
  } catch { /* SSR or storage-blocked env */ }
  // Priority 2: localStorage.
  try {
    return localStorage.getItem(API_KEY_STORAGE) || "";
  } catch {
    return "";
  }
}

let _apiKey = _initApiKey();

export function getApiKey() {
  return _apiKey;
}

export function setApiKey(key) {
  _apiKey = String(key || "");
  try {
    if (_apiKey) localStorage.setItem(API_KEY_STORAGE, _apiKey);
    else localStorage.removeItem(API_KEY_STORAGE);
  } catch { /* ignore */ }
}

export function clearApiKey() {
  setApiKey("");
}

function _authHeaders(extra = {}) {
  const h = { ...extra };
  if (_apiKey) h["X-API-Key"] = _apiKey;
  return h;
}

function _dispatchUnauthorized(status, path) {
  try {
    window.dispatchEvent(new CustomEvent("ag:unauthorized", {
      detail: { status, path, hasKey: !!_apiKey },
    }));
  } catch { /* ignore */ }
}

async function _checkResponse(res, path) {
  if (res.status === 401 || res.status === 403) {
    _dispatchUnauthorized(res.status, path);
    const err = await res.json().catch(() => ({}));
    const e = new Error(err.error || err.detail || `${res.status} ${res.statusText}`);
    e.status = res.status;
    throw e;
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const e = new Error(err.detail || err.error || `${res.status} ${res.statusText}`);
    e.status = res.status;
    throw e;
  }
  return res;
}

async function request(path, { signal } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    cache: "no-store",
    headers: _authHeaders(),
    signal,
  });
  await _checkResponse(res, path);
  return res.json();
}

async function post(path, body, { signal } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: _authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
    signal,
  });
  await _checkResponse(res, path);
  return res.json();
}

async function del(path, body, { signal } = {}) {
  const init = {
    method: "DELETE",
    headers: _authHeaders(body ? { "Content-Type": "application/json" } : {}),
    signal,
  };
  if (body) init.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, init);
  await _checkResponse(res, path);
  return res.json();
}

// ─────────────────────────────────────────────────────────────────────────
// WebSocket
// ─────────────────────────────────────────────────────────────────────────
function getWsBase() {
  const loc = window.location;
  const proto = loc.protocol === "https:" ? "wss:" : "ws:";
  const host = BASE ? new URL(BASE).host : loc.host;
  return `${proto}//${host}`;
}

export function createScanSocket(jobId, onMessage) {
  const url = `${getWsBase()}/ws/scan/${jobId}`;
  let ws = null;
  let alive = true;
  let reconnectTimer = null;

  function connect() {
    if (!alive) return;
    try {
      // Backend accepts the API key via a `[protocol, key]` subprotocol pair,
      // or via the `X-API-Key` header. Browsers don't let us set arbitrary
      // headers on the WS handshake, so we use the subprotocol variant. See
      // `ui/api/server.py:ws_scan_feed`.
      if (_apiKey) {
        ws = new WebSocket(url, ["api-key", _apiKey]);
      } else {
        ws = new WebSocket(url);
      }
    } catch {
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      console.log("[WS] Connected to", jobId);
    };

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type !== "pong") onMessage(data);
      } catch { /* ignore malformed frames */ }
    };

    ws.onclose = (evt) => {
      // 4401 is our application-defined "unauthorized" close code from the
      // backend. Surface it once and stop retrying — reconnecting with the
      // same key would loop forever.
      if (evt && evt.code === 4401) {
        alive = false;
        _dispatchUnauthorized(4401, url);
        return;
      }
      if (alive) scheduleReconnect();
    };

    ws.onerror = () => {
      try { ws.close(); } catch { /* ignore */ }
    };
  }

  function scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, 3000);
  }

  connect();

  // Keepalive ping every 25s
  const pingInterval = setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action: "ping" }));
    }
  }, 25000);

  return {
    close() {
      alive = false;
      clearInterval(pingInterval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) try { ws.close(); } catch { /* ignore */ }
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────
// API surface
// ─────────────────────────────────────────────────────────────────────────
export const api = {
  // ── Auth helpers (exposed for the Settings page) ──
  getApiKey,
  setApiKey,
  clearApiKey,

  getSourceIp: () => request("/api/source-ip"),
  getTargets: () => request("/api/targets"),
  addTarget: (data) => post("/api/targets", data),
  deleteTarget: (id) => del(`/api/targets/${id}`),
  getScans: () => request("/api/scans"),
  getScan: (id) => request(`/api/scans/${id}`),
  getVulnerabilities: (id) => request(`/api/scans/${id}/vulnerabilities`),
  getAuditTrail: () => request("/api/audit-trail"),
  getExecutionLog: () => request("/api/execution-log"),
  getPoc: () => request("/api/poc"),
  getStats: () => request("/api/stats"),
  startScan: (data) => post("/api/scans/run", data),
  runScan: (data) => post("/api/scans/run", data),
  getActiveScans: () => request("/api/scans/active"),
  getActiveScan: () => request("/api/scans/active").then(list => (Array.isArray(list) ? list[0] : list) || null).catch(() => null),
  getScanJob: (id) => request(`/api/scans/job/${id}`),
  getScanLogs: (id, tail = 200) => request(`/api/scans/job/${id}/logs?tail=${tail}`),
  getScanLogsFull: (id) => request(`/api/scans/job/${id}/logs-full`),
  // Download URLs must carry the API key too — the browser cannot set headers
  // on a top-level navigation. `?api_key` is accepted by the backend
  // middleware only for download-style GETs; scoped narrowly.
  getScanLogsDownloadUrl: (id) => `${BASE}/api/scans/job/${id}/logs-download${_apiKey ? `?api_key=${encodeURIComponent(_apiKey)}` : ""}`,
  getScanStatus: (id) => request(`/api/scans/job/${id}`).catch(() => null),
  stopScan: (id) => post(`/api/scans/job/${id}/stop`, {}),
  cancelScan: (id) => post(`/api/scans/job/${id}/cancel`, {}),
  resumeScan: (data) => post("/api/scans/resume", data),
  getReportUrl: (id) => `${BASE}/api/scans/${id}/report${_apiKey ? `?api_key=${encodeURIComponent(_apiKey)}` : ""}`,
  compareScans: (a, b) => request(`/api/scans/compare?a=${a}&b=${b}`),
  getSarif: (id) => request(`/api/scans/${id}/sarif`),
  getGitLabDast: (id) => request(`/api/scans/${id}/gitlab-dast`),
  getSarifUrl: (id) => `${BASE}/api/scans/${id}/sarif${_apiKey ? `?api_key=${encodeURIComponent(_apiKey)}` : ""}`,
  getExploitReports: (id) => request(`/api/scans/${id}/exploit-reports`),
  getExecutiveSummary: (id) => request(`/api/scans/${id}/executive-summary`),
  getEvidenceList: () => request("/api/evidence"),
  getEvidenceUrl: (filename) => `${BASE}/api/evidence/${filename}${_apiKey ? `?api_key=${encodeURIComponent(_apiKey)}` : ""}`,
  getSchedules: () => request("/api/schedules"),
  addSchedule: (data) => post("/api/schedules", data),
  deleteSchedule: (id) => del(`/api/schedules/${id}`),
  toggleSchedule: (id) => post(`/api/schedules/${id}/toggle`, {}),
  startScheduler: () => post("/api/scheduler/start", {}),
  getCampaigns: () => request("/api/campaigns"),
  runCampaign: (data) => post("/api/campaigns/run", data),
  getCampaignProgress: () => request("/api/campaigns/progress"),
  getLiveProgress: (scanId) => request(`/api/scans/live-progress${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`).catch(() => ({})),
  getLiveResults: (scanId) => request(`/api/scans/live-results${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`).catch(() => ({
    recon: { subdomains: [], endpoints: [], technologies: {}, ports: [], ips: [] },
    vulnerabilities: [], exploits: [], captured_requests: [],
  })),
  getToolOutputs: (id) => request(`/api/scans/${id}/tool-outputs`),
  getActivity: (id) => request(`/api/scans/${id}/activity`),

  // ── Scan artifacts (PoC, screenshots, SARIF, nuclei templates, canonical) ──
  listScanArtifacts: (scanId, kind = "") =>
    request(`/api/scans/${scanId}/artifacts${kind ? `?kind=${encodeURIComponent(kind)}` : ""}`)
      .catch(() => ({ scan_id: scanId, count: 0, counts_by_kind: {}, artifacts: [] })),
  getScanPocs: (scanId) =>
    request(`/api/scans/${scanId}/pocs`).catch(() => ({ scan_id: scanId, pocs: {} })),
  listScanScreenshots: (scanId) =>
    request(`/api/scans/${scanId}/screenshots`).catch(() => ({ scan_id: scanId, count: 0, screenshots: [] })),
  scanArtifactUrl: (scanId, artifactId, download = false) => {
    const q = new URLSearchParams();
    if (download) q.set("download", "true");
    if (_apiKey) q.set("api_key", _apiKey);
    const qs = q.toString();
    return `/api/scans/${scanId}/artifacts/${artifactId}${qs ? "?" + qs : ""}`;
  },

  // Auth bypasses — "Access Gained"
  getAuthBypasses: (scanId) =>
    request(`/api/scans/${scanId}/auth-bypasses`)
      .catch(() => ({ scan_id: scanId, count: 0, bypasses: [] })),

  // Live parallel-agent view
  getLiveAgents: (scanId) =>
    request(`/api/scans/${scanId}/agents/live`)
      .catch(() => ({ scan_id: scanId, count: 0, counts_by_status: {}, agents: [] })),

  // Scan chatbot
  askScanChat: (scanId, message, history = []) =>
    post(`/api/scans/${scanId}/chat`, { message, history }),

  // Per-agent reasoning
  getAgentReasoning: (scanId, agentId = "", limit = 50) =>
    request(`/api/scans/${scanId}/agents/reasoning?agent_id=${encodeURIComponent(agentId)}&limit=${limit}`)
      .catch(() => ({ scan_id: scanId, count: 0, reasoning: [] })),

  // Attack chains — one canonical entry (dedup key fix: duplicate `getAttackChains`
  // key on this object was silently overwriting the earlier definition).
  getAttackChains: (scanId) =>
    request(`/api/scans/${scanId}/attack-chains`)
      .catch(() => ({ scan_id: scanId, count: 0, chains: [] })),
  regenerateAttackChains: (scanId) => post(`/api/scans/${scanId}/attack-chains/regenerate`, {}),

  // Scan diff
  diffScans: (currentId, baselineId) =>
    request(`/api/scans/${currentId}/diff/${baselineId}`),

  // Repro bundles regenerate
  regenerateReproBundles: (scanId) => post(`/api/scans/${scanId}/repro-bundles/regenerate`, {}),

  // Review queue — one canonical entry
  getReviewQueue: () => request("/api/review-queue"),
  getReviewSuccesses: () => request("/api/review-queue/successes"),
  getReviewManual: () => request("/api/review-queue/manual"),
  resolveReview: (id, note = "") => post(`/api/review-queue/${id}/resolve`, { note }),

  killAllScans: () => post("/api/scans/kill-all", {}),

  // Canonical state
  getCanonicalSummary: () => request("/api/canonical/summary"),
  getCanonicalCoverage: () => request("/api/canonical/coverage"),
  getCanonicalConvergence: () => request("/api/canonical/convergence"),
  getCanonicalAttackSurface: () => request("/api/canonical/attack-surface"),
  getCanonicalLearning: () => request("/api/canonical/learning"),
  getCanonicalHealth: () => request("/api/canonical/health"),

  // Strix patterns
  getCoverageTracker: () => request("/api/coverage/tracker"),
  getHonestCoverage: () => request("/api/coverage/honest"),
  getSkills: () => request("/api/skills"),
  getConfidenceSummary: () => request("/api/confidence/summary"),
  getErrorStats: () => request("/api/error-stats"),

  // Intelligence
  getDecisionLog: () => request("/api/decision-log"),
  getExperiences: () => request("/api/experiences"),
  getStrategies: () => request("/api/strategies"),
  getLlmFailures: () => request("/api/llm-failures"),
  getFindingsV2: () => request("/api/findings-v2"),
  getFindingsV2Confirmed: () => request("/api/findings-v2/confirmed"),
  getExploitResults: (id) => request(`/api/scans/${id}/exploit-results`),
  getDedupStats: () => request("/api/dedup-stats"),
  getCollectedData: (id) => request(`/api/scans/${id}/collected-data`),
  getPostExploit: (id, type) => request(`/api/scans/${id}/post-exploit${type ? '?data_type=' + type : ''}`),
  getScanMetadata: (id, key) => request(`/api/scans/${id}/metadata${key ? '?key=' + key : ''}`),

  // RAG Knowledge Base
  ragInit: () => post("/api/rag/init", {}),
  ragStats: () => request("/api/rag/stats"),
  ragIngestText: (text, title, metadata) => post("/api/rag/ingest/text", { text, title, metadata: metadata || {} }),
  ragIngestUrl: (url, metadata) => post("/api/rag/ingest/url", { url, metadata: metadata || {} }),
  ragSearch: (query, max_results) => post("/api/rag/ingest/search", { query, max_results: max_results || 3 }),
  ragQuery: (query, top_k, category) => post("/api/rag/query", { query, top_k: top_k || 5, category: category || "" }),
  ragDelete: (source_type, source_ref) => del("/api/rag/documents", { source_type, source_ref: source_ref || "" }),
  ragListDocuments: (source_type, limit, offset) =>
    request(`/api/rag/documents?${new URLSearchParams({
      ...(source_type ? { source_type } : {}),
      limit: limit || 100,
      offset: offset || 0,
    })}`),
  ragDeleteDoc: (doc_id) => del(`/api/rag/documents/${doc_id}`),
  ragUploadFile: async (file, metadata) => {
    const form = new FormData();
    form.append("file", file);
    form.append("metadata", JSON.stringify(metadata || {}));
    const res = await fetch(`${BASE}/api/rag/ingest/uploaded`, {
      method: "POST",
      // NB: don't set Content-Type; the browser sets multipart boundary.
      headers: _authHeaders(),
      body: form,
    });
    await _checkResponse(res, "/api/rag/ingest/uploaded");
    return res.json();
  },
};

// ─────────────────────────────────────────────────────────────────────────
// Polling helper — closes the WS+poll race (#087).
//
// Usage:
//   useEffect(() => {
//     const poll = createPoller(() => api.getLiveProgress(scanId), setProgress, 8000);
//     return () => poll.stop();
//   }, [scanId]);
//
// - Uses AbortController so a slow in-flight fetch is cancelled when the effect
//   unmounts.
// - Uses a monotonically-increasing generation counter so a delayed response
//   from an older request cannot overwrite state from a newer request.
// ─────────────────────────────────────────────────────────────────────────
export function createPoller(fetchFn, onData, intervalMs = 5000) {
  let stopped = false;
  let gen = 0;
  let timer = null;
  let controller = null;

  async function tick() {
    if (stopped) return;
    const myGen = ++gen;
    controller = new AbortController();
    try {
      const data = await fetchFn({ signal: controller.signal });
      if (!stopped && myGen === gen) onData(data);
    } catch (e) {
      if (e && e.name === "AbortError") return;
      // Errors are silently dropped for pollers — the UI keeps its last known
      // state. The global `ag:unauthorized` listener still gets 401 events.
    } finally {
      if (!stopped) timer = setTimeout(tick, intervalMs);
    }
  }
  tick();

  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (controller) try { controller.abort(); } catch { /* ignore */ }
    },
  };
}
