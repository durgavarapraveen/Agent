const BASE = window.__ANTIGRAVITY_API__ || "";

async function request(path) {
  const res = await fetch(`${BASE}${path}`);
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
  getSchedules: () => request("/api/schedules"),
  addSchedule: (data) => post("/api/schedules", data),
  deleteSchedule: (id) => del(`/api/schedules/${id}`),
  toggleSchedule: (id) => post(`/api/schedules/${id}/toggle`, {}),
  startScheduler: () => post("/api/scheduler/start", {}),
  getCampaigns: () => request("/api/campaigns"),
  runCampaign: (data) => post("/api/campaigns/run", data),
  getCampaignProgress: () => request("/api/campaigns/progress"),
  getLiveProgress: () => request("/api/scans/live-progress").catch(() => ({})),
  getLiveResults: () => request("/api/scans/live-results").catch(() => ({
    recon: { subdomains: [], endpoints: [], technologies: {}, ports: [], ips: [] },
    vulnerabilities: [], exploits: [], captured_requests: [],
  })),
  getToolOutputs: (id) => request(`/api/scans/${id}/tool-outputs`),
  getActivity: (id) => request(`/api/scans/${id}/activity`),
  getReviewQueue: () => request("/api/review-queue"),
  getReviewSuccesses: () => request("/api/review-queue/successes"),
  getReviewManual: () => request("/api/review-queue/manual"),
  resolveReview: (id, note = "") => post(`/api/review-queue/${id}/resolve`, { note }),
  killAllScans: () => post("/api/scans/kill-all", {}),
};
