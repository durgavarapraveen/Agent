const BASE = window.__ANTIGRAVITY_API__ || "";

async function request(path) {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `${res.status}`);
  }
  return res.json();
}

async function del(path) {
  const res = await fetch(`${BASE}${path}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

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
      ws = new WebSocket(url);
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
      } catch {}
    };

    ws.onclose = () => {
      if (alive) scheduleReconnect();
    };

    ws.onerror = () => {
      try { ws.close(); } catch {}
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
      if (ws) try { ws.close(); } catch {}
    },
  };
}

export const api = {
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
  getScanLogsDownloadUrl: (id) => `${BASE}/api/scans/job/${id}/logs-download`,
  getScanStatus: (id) => request(`/api/scans/job/${id}`).catch(() => null),
  stopScan: (id) => post(`/api/scans/job/${id}/stop`, {}),
  cancelScan: (id) => post(`/api/scans/job/${id}/cancel`, {}),
  resumeScan: (data) => post("/api/scans/resume", data),
  getReportUrl: (id) => `${BASE}/api/scans/${id}/report`,
  compareScans: (a, b) => request(`/api/scans/compare?a=${a}&b=${b}`),
  getSarif: (id) => request(`/api/scans/${id}/sarif`),
  getGitLabDast: (id) => request(`/api/scans/${id}/gitlab-dast`),
  getSarifUrl: (id) => `${BASE}/api/scans/${id}/sarif`,
  getExploitReports: (id) => request(`/api/scans/${id}/exploit-reports`),
  getExecutiveSummary: (id) => request(`/api/scans/${id}/executive-summary`),
  getEvidenceList: () => request("/api/evidence"),
  getEvidenceUrl: (filename) => `${BASE}/api/evidence/${filename}`,
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
  scanArtifactUrl: (scanId, artifactId, download = false) =>
    `/api/scans/${scanId}/artifacts/${artifactId}${download ? "?download=true" : ""}`,
  // Auth bypasses — "Access Gained" — every successful login/bypass with payload + proof
  getAuthBypasses: (scanId) =>
    request(`/api/scans/${scanId}/auth-bypasses`)
      .catch(() => ({ scan_id: scanId, count: 0, bypasses: [] })),
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
  getAttackChains: (id) => request(`/api/scans/${id}/attack-chains`),
  getPostExploit: (id, type) => request(`/api/scans/${id}/post-exploit${type ? '?data_type=' + type : ''}`),
  getScanMetadata: (id, key) => request(`/api/scans/${id}/metadata${key ? '?key=' + key : ''}`),
  getExploitReports: (id) => request(`/api/scans/${id}/exploit-reports`),
  getReviewQueue: () => request("/api/review-queue"),
  // RAG Knowledge Base
  ragInit: () => post("/api/rag/init", {}),
  ragStats: () => request("/api/rag/stats"),
  ragIngestText: (text, title, metadata) => post("/api/rag/ingest/text", { text, title, metadata: metadata || {} }),
  ragIngestUrl: (url, metadata) => post("/api/rag/ingest/url", { url, metadata: metadata || {} }),
  ragSearch: (query, max_results) => post("/api/rag/ingest/search", { query, max_results: max_results || 3 }),
  ragQuery: (query, top_k, category) => post("/api/rag/query", { query, top_k: top_k || 5, category: category || "" }),
  ragDelete: (source_type, source_ref) => fetch(`${BASE}/api/rag/documents`, {
    method: "DELETE", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_type, source_ref: source_ref || "" }),
  }).then(r => r.json()),
  ragListDocuments: (source_type, limit, offset) => request(`/api/rag/documents?${new URLSearchParams({...(source_type ? {source_type} : {}), limit: limit || 100, offset: offset || 0})}`),
  ragDeleteDoc: (doc_id) => fetch(`${BASE}/api/rag/documents/${doc_id}`, { method: "DELETE" }).then(r => r.json()),
  ragUploadFile: async (file, metadata) => {
    const form = new FormData();
    form.append("file", file);
    form.append("metadata", JSON.stringify(metadata || {}));
    const res = await fetch(`${BASE}/api/rag/ingest/uploaded`, { method: "POST", body: form });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail || `${res.status}`); }
    return res.json();
  },
};
