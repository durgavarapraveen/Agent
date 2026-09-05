import React, { useState, useEffect } from "react";

/* ── Recon sub-nav sections ─────────────────────────────────────────────── */
const SECTIONS = [
  { key: "overview", label: "Overview" },
  { key: "subdomains", label: "Subdomains" },
  { key: "endpoints", label: "Endpoints" },
  { key: "ports", label: "Ports" },
  { key: "dns", label: "DNS Records" },
  { key: "osint", label: "OSINT" },
  { key: "infra", label: "Infrastructure" },
  { key: "secrets", label: "Secrets" },
  { key: "requests", label: "Requests" },
  { key: "tools", label: "Tool Results" },
];

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function count(v) {
  if (!v) return 0;
  if (Array.isArray(v)) return v.length;
  if (typeof v === "object") return Object.keys(v).length;
  return 0;
}

function SectionHeader({ title, count: n, icon, accent }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
      {icon && <span style={{ fontSize: 16, opacity: 0.6 }}>{icon}</span>}
      <h3 style={{ marginBottom: 0 }}>{title}</h3>
      {n > 0 && (
        <span style={{
          fontSize: 11, fontWeight: 600, padding: "2px 10px", borderRadius: 100,
          background: accent ? `${accent}18` : "rgba(175,80,255,0.1)",
          color: accent || "var(--accent)",
          fontFamily: "var(--mono)",
        }}>{n}</span>
      )}
    </div>
  );
}

function DataTable({ columns, rows, maxHeight = 400 }) {
  if (!rows?.length) return null;
  return (
    <div className="table-wrap" style={{ maxHeight }}>
      <table>
        <thead>
          <tr>{columns.map(c => <th key={c.key} style={c.style}>{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map(c => <td key={c.key} style={c.tdStyle}>{c.render ? c.render(row, i) : row[c.key]}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StatBox({ label, value, accent, icon }) {
  const cls = accent ? `stat-card accent-${accent}` : "stat-card";
  return (
    <div className={cls} style={{ padding: "14px 18px", minWidth: 0 }}>
      <span className="label">{label}</span>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
        <span className="value" style={{ fontSize: 26 }}>{value}</span>
        {icon && <span style={{ fontSize: 14, opacity: 0.5 }}>{icon}</span>}
      </div>
    </div>
  );
}

function Pill({ children, color, bg }) {
  return (
    <span style={{
      display: "inline-block", padding: "3px 10px", borderRadius: 100,
      fontSize: 11, fontWeight: 500, fontFamily: "var(--mono)",
      color: color || "var(--text)", background: bg || "rgba(247,249,250,0.04)",
      border: "1px solid var(--border)", letterSpacing: 0.3,
    }}>{children}</span>
  );
}

function EmptyState({ message }) {
  return <div className="empty" style={{ padding: "32px 20px", fontSize: 13 }}>{message}</div>;
}

/* ── Overview Section ────────────────────────────────────────────────────── */
function OverviewSection({ context }) {
  const osintSummary = context.osint?.summary || {};
  const liveCount = context.subdomain_summary?.live || 0;
  const deadCount = context.subdomain_summary?.dead || 0;

  return (
    <>
      <div className="card-grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))" }}>
        <StatBox label="Subdomains" value={count(context.subdomains)} accent="purple" />
        <StatBox label="Endpoints" value={count(context.endpoints)} accent="blue" />
        <StatBox label="Open Ports" value={count(context.ports)} accent="green" />
        <StatBox label="DNS Records" value={count(context.dns_records)} accent="cyan" />
        <StatBox label="Directories" value={count(context.directories)} accent="yellow" />
        <StatBox label="Secrets" value={count(context.secrets)} accent="red" />
        <StatBox label="Technologies" value={count(context.technologies)} accent="orange" />
      </div>

      <div className="two-col" style={{ marginBottom: 16 }}>
        <div className="card" style={{ padding: 16 }}>
          <h3>Attack Surface</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Live Hosts</span>
              <span style={{ color: "var(--green)", fontWeight: 600, fontFamily: "var(--mono)" }}>{liveCount}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Dead Hosts</span>
              <span style={{ color: "var(--red)", fontWeight: 600, fontFamily: "var(--mono)" }}>{deadCount}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>SSL/TLS Hosts</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{count(context.ssl_info)}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Header Profiles</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{count(context.headers)}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Captured Requests</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{count(context.captured_requests)}</span>
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: 16 }}>
          <h3>OSINT Summary</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Employees Found</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{osintSummary.employees || 0}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Leaked Credentials</span>
              <span style={{ color: (osintSummary.leaked_credentials || 0) > 0 ? "var(--red)" : "inherit", fontWeight: 600, fontFamily: "var(--mono)" }}>{osintSummary.leaked_credentials || 0}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Cloud Buckets</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{osintSummary.cloud_buckets || 0}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>Threat Hits</span>
              <span style={{ color: (osintSummary.threat_correlations || 0) > 0 ? "var(--orange)" : "inherit", fontWeight: 600, fontFamily: "var(--mono)" }}>{osintSummary.threat_correlations || 0}</span>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "var(--text-dim)" }}>OSINT Findings</span>
              <span style={{ fontWeight: 600, fontFamily: "var(--mono)" }}>{count(context.osint?.findings)}</span>
            </div>
          </div>
        </div>
      </div>

      {context.technologies && Object.keys(context.technologies).length > 0 && (
        <div className="card" style={{ padding: 16 }}>
          <h3>Technology Stack</h3>
          {Object.entries(context.technologies).map(([host, techs]) => (
            <div key={host} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6, fontFamily: "var(--mono)", fontWeight: 500 }}>{host}</div>
              <div className="pill-row">
                {(Array.isArray(techs) ? techs : []).map((t, i) => <Pill key={i}>{t}</Pill>)}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/* ── Subdomains Section ──────────────────────────────────────────────────── */
function SubdomainsSection({ subdomains, summary }) {
  const [filter, setFilter] = useState("all");
  if (!subdomains?.length) return <EmptyState message="No subdomains discovered" />;

  const filtered = filter === "all" ? subdomains
    : filter === "live" ? subdomains.filter(s => typeof s === "object" && s.live)
    : subdomains.filter(s => typeof s === "object" && s.status && s.status !== "unknown" && !s.live);

  return (
    <>
      <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center" }}>
        {["all", "live", "dead"].map(f => (
          <button key={f} className={`btn btn-sm ${filter === f ? "btn-primary" : ""}`}
            onClick={() => setFilter(f)} style={{ textTransform: "capitalize" }}>
            {f} {f === "all" ? `(${subdomains.length})` : f === "live" ? `(${summary?.live || 0})` : `(${summary?.dead || 0})`}
          </button>
        ))}
      </div>
      <DataTable
        maxHeight={500}
        columns={[
          { key: "status", label: "Status", style: { width: 80 }, render: (s) => {
            const obj = typeof s === "object" ? s : {};
            const live = obj.live;
            const known = obj.status && obj.status !== "unknown";
            const label = live ? "LIVE" : known ? "DEAD" : "?";
            const color = live ? "var(--green)" : known ? "var(--red)" : "var(--text-dim)";
            const bg = live ? "var(--green-dim)" : known ? "var(--red-dim)" : "rgba(255,255,255,0.04)";
            return <span className="badge" style={{ background: bg, color, border: "none", fontSize: 10 }}>{label}</span>;
          }},
          { key: "name", label: "Hostname", tdStyle: { fontFamily: "var(--mono)", fontSize: 13, color: "var(--text-h)" }, render: (s) => {
            return typeof s === "string" ? s : (s.name || s.subdomain || JSON.stringify(s));
          }},
          { key: "code", label: "HTTP", style: { width: 70 }, tdStyle: { fontFamily: "var(--mono)", fontSize: 12 }, render: (s) => {
            if (typeof s !== "object" || !s.status_code) return "-";
            const code = s.status_code;
            const color = code < 300 ? "var(--green)" : code < 400 ? "var(--yellow)" : "var(--red)";
            return <span style={{ color }}>{code}</span>;
          }},
          { key: "note", label: "Note", tdStyle: { fontSize: 12, color: "var(--text-dim)", fontStyle: "italic" }, render: (s) => {
            return typeof s === "object" ? (s.note || "") : "";
          }},
        ]}
        rows={filtered}
      />
    </>
  );
}

/* ── Endpoints Section ───────────────────────────────────────────────────── */
function EndpointsSection({ endpoints }) {
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  if (!endpoints?.length) return <EmptyState message="No endpoints discovered" />;

  const kinds = [...new Set(endpoints.map(ep => (typeof ep === "object" ? ep.kind : "") || "").filter(Boolean))];

  const filtered = endpoints.filter(ep => {
    const obj = typeof ep === "object" ? ep : { url: ep };
    const url = obj.url || obj.path || "";
    const kind = obj.kind || "";
    if (search && !url.toLowerCase().includes(search.toLowerCase())) return false;
    if (kindFilter !== "all" && kind !== kindFilter) return false;
    return true;
  });

  const methodColors = { GET: "var(--green)", POST: "#ca8a04", PUT: "var(--blue)", DELETE: "var(--red)", PATCH: "var(--purple)" };

  return (
    <>
      <div className="filter-bar">
        <input type="text" placeholder="Search endpoints..." value={search} onChange={e => setSearch(e.target.value)} style={{ minWidth: 240 }} />
        <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}>
          <option value="all">All types ({endpoints.length})</option>
          {kinds.map(k => <option key={k} value={k}>{k.toUpperCase()}</option>)}
        </select>
      </div>
      <DataTable
        maxHeight={500}
        columns={[
          { key: "method", label: "Method", style: { width: 80 }, render: (ep) => {
            const m = (typeof ep === "object" ? ep.method : "GET") || "GET";
            return <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 11, color: methodColors[m] || "var(--text)" }}>{m}</span>;
          }},
          { key: "url", label: "URL", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-h)", wordBreak: "break-all" }, render: (ep) => {
            const obj = typeof ep === "object" ? ep : {};
            return obj.url || obj.path || String(ep);
          }},
          { key: "kind", label: "Type", style: { width: 110 }, render: (ep) => {
            const kind = typeof ep === "object" ? ep.kind : "";
            if (!kind) return null;
            const colors = { api: "var(--accent)", sensitive: "var(--red)", parameterized: "var(--orange)", page: "var(--text-dim)" };
            return <Pill color={colors[kind] || "var(--text-dim)"} bg={`${colors[kind] || "var(--text-dim)"}12`}>{kind}</Pill>;
          }},
        ]}
        rows={filtered}
      />
    </>
  );
}

/* ── Ports Section ───────────────────────────────────────────────────────── */
function PortsSection({ ports }) {
  if (!ports?.length) return <EmptyState message="No open ports discovered" />;
  return (
    <DataTable
      maxHeight={500}
      columns={[
        { key: "port", label: "Port", style: { width: 90 }, tdStyle: { fontFamily: "var(--mono)", fontWeight: 700, fontSize: 14, color: "var(--green)" }, render: (p) => {
          if (typeof p !== "object") return String(p);
          return `${p.port || p.port_number || "?"}/${p.protocol || "tcp"}`;
        }},
        { key: "service", label: "Service", tdStyle: { fontFamily: "var(--mono)", fontSize: 13, color: "var(--text-h)" }, render: (p) => {
          return typeof p === "object" ? (p.service_name || p.service || "-") : "-";
        }},
        { key: "version", label: "Version", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-dim)" }, render: (p) => {
          return typeof p === "object" ? (p.version || "-") : "-";
        }},
        { key: "host", label: "Host", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-dim)" }, render: (p) => {
          return typeof p === "object" ? (p.host || "-") : "-";
        }},
      ]}
      rows={ports}
    />
  );
}

/* ── OSINT Section ───────────────────────────────────────────────────────── */
function OsintSection({ osint }) {
  const [osintTab, setOsintTab] = useState("people");
  if (!osint || typeof osint !== "object") return <EmptyState message="No OSINT data collected" />;

  const s = osint.summary || {};
  const tabs = [
    { key: "people", label: "People", count: count(osint.employees) },
    { key: "creds", label: "Leaked Creds", count: count(osint.leaked_credentials) },
    { key: "threats", label: "Threats", count: count(osint.threat_correlations) },
    { key: "findings", label: "Findings", count: count(osint.findings) },
    { key: "dns", label: "DNS/Mail Intel", count: count(osint.domain_intelligence) },
  ];
  if (osint.other?.github_profiles?.length) tabs.push({ key: "github", label: "GitHub", count: osint.other.github_profiles.length });
  if (osint.cloud_buckets?.length) tabs.push({ key: "buckets", label: "Cloud Buckets", count: osint.cloud_buckets.length });

  return (
    <>
      <div className="card-grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", marginBottom: 16 }}>
        <StatBox label="Employees" value={s.employees || 0} accent="blue" />
        <StatBox label="Leaked Creds" value={s.leaked_credentials || 0} accent="red" />
        <StatBox label="Cloud Buckets" value={s.cloud_buckets || 0} accent="cyan" />
        <StatBox label="Threat Hits" value={s.threat_correlations || 0} accent="orange" />
      </div>

      <div className="tabs" style={{ marginBottom: 16 }}>
        {tabs.map(t => (
          <button key={t.key} className={`tab ${osintTab === t.key ? "active" : ""}`} onClick={() => setOsintTab(t.key)}>
            {t.label} {t.count > 0 && <span style={{ fontSize: 11, opacity: 0.6 }}>({t.count})</span>}
          </button>
        ))}
      </div>

      {osintTab === "people" && osint.employees?.length > 0 && (
        <DataTable
          columns={[
            { key: "name", label: "Name", tdStyle: { fontWeight: 600, color: "var(--text-h)" }, render: (e) => typeof e === "string" ? e : (e.name || e.email || JSON.stringify(e)) },
            { key: "email", label: "Email", tdStyle: { fontFamily: "var(--mono)", fontSize: 12 }, render: (e) => typeof e === "object" ? (e.email || "-") : "-" },
            { key: "title", label: "Role", tdStyle: { fontSize: 12, color: "var(--text-dim)" }, render: (e) => typeof e === "object" ? (e.title || "-") : "-" },
            { key: "source", label: "Source", tdStyle: { fontSize: 11, color: "var(--text-dim)" }, render: (e) => typeof e === "object" ? (e.source || "-") : "-" },
          ]}
          rows={osint.employees}
        />
      )}

      {osintTab === "creds" && osint.leaked_credentials?.length > 0 && (
        <DataTable
          columns={[
            { key: "type", label: "Type", style: { width: 160 }, render: (c) => <span className="badge critical" style={{ fontSize: 10 }}>{c.type || "credential"}</span> },
            { key: "username", label: "Username", tdStyle: { fontFamily: "var(--mono)", fontWeight: 600, color: "var(--text-h)" }, render: (c) => c.username || "?" },
            { key: "secret", label: "Secret", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--red)", wordBreak: "break-all" }, render: (c) => c.secret || "-" },
            { key: "source", label: "Source", tdStyle: { fontSize: 11, color: "var(--text-dim)" }, render: (c) => c.source || "-" },
          ]}
          rows={osint.leaked_credentials}
        />
      )}

      {osintTab === "threats" && osint.threat_correlations?.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {osint.threat_correlations.map((t, i) => {
            const txt = typeof t === "string" ? t : JSON.stringify(t);
            return (
              <div key={i} className="card" style={{ padding: 14 }}>
                <pre style={{ fontFamily: "var(--mono)", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text)", margin: 0, lineHeight: 1.6 }}>{txt}</pre>
              </div>
            );
          })}
        </div>
      )}

      {osintTab === "findings" && osint.findings?.length > 0 && (
        <div style={{ maxHeight: 500, overflowY: "auto" }}>
          {osint.findings.map((f, i) => {
            const txt = typeof f === "string" ? f : (f.name || f.title || JSON.stringify(f));
            return (
              <div key={i} style={{ padding: "8px 0", fontSize: 13, borderBottom: "1px solid var(--border)", color: "var(--text)" }}>{txt}</div>
            );
          })}
        </div>
      )}

      {osintTab === "dns" && osint.domain_intelligence && Object.keys(osint.domain_intelligence).length > 0 && (
        <div className="card" style={{ padding: 16 }}>
          <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: "8px 16px" }}>
            {Object.entries(osint.domain_intelligence).map(([k, v]) => (
              <React.Fragment key={k}>
                <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600, color: "var(--accent)" }}>{k}</span>
                <span style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", wordBreak: "break-all" }}>{typeof v === "string" ? v : JSON.stringify(v)}</span>
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {osintTab === "github" && osint.other?.github_profiles?.length > 0 && (
        <DataTable
          columns={[
            { key: "user", label: "Username", tdStyle: { fontFamily: "var(--mono)", fontWeight: 600, color: "var(--text-h)" }, render: (g) => g.username || (typeof g === "string" ? g : JSON.stringify(g)) },
            { key: "source", label: "Source", tdStyle: { fontSize: 12, color: "var(--text-dim)" }, render: (g) => g.source || "-" },
          ]}
          rows={osint.other.github_profiles}
        />
      )}

      {osintTab === "buckets" && osint.cloud_buckets?.length > 0 && (
        <DataTable
          columns={[
            { key: "bucket", label: "Bucket", tdStyle: { fontFamily: "var(--mono)", color: "var(--text-h)" }, render: (b) => typeof b === "string" ? b : (b.name || JSON.stringify(b)) },
          ]}
          rows={osint.cloud_buckets}
        />
      )}
    </>
  );
}

/* ── DNS Records Section ────────────────────────────────────────────────── */
function DnsSection({ records }) {
  const [typeFilter, setTypeFilter] = useState("all");
  if (!records?.length) return <EmptyState message="No DNS records captured" />;

  const types = [...new Set(records.map(r => r.type).filter(Boolean))].sort();
  const filtered = typeFilter === "all" ? records : records.filter(r => r.type === typeFilter);
  const typeColors = { A: "var(--green)", AAAA: "var(--blue)", CNAME: "var(--cyan)", MX: "var(--orange)", NS: "var(--purple)", SOA: "var(--yellow)", TXT: "var(--text-dim)", SRV: "var(--accent)", PTR: "var(--red)" };

  return (
    <>
      <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center", flexWrap: "wrap" }}>
        <button className={`btn btn-sm ${typeFilter === "all" ? "btn-primary" : ""}`}
          onClick={() => setTypeFilter("all")}>All ({records.length})</button>
        {types.map(t => (
          <button key={t} className={`btn btn-sm ${typeFilter === t ? "btn-primary" : ""}`}
            onClick={() => setTypeFilter(t)}>{t} ({records.filter(r => r.type === t).length})</button>
        ))}
      </div>
      <DataTable
        maxHeight={500}
        columns={[
          { key: "type", label: "Type", style: { width: 70 }, render: (r) => (
            <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 11, color: typeColors[r.type] || "var(--text)" }}>{r.type}</span>
          )},
          { key: "name", label: "Name", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-h)" }, render: (r) => r.name || "-" },
          { key: "value", label: "Value", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--accent)", wordBreak: "break-all" }, render: (r) => r.value || "-" },
          { key: "ttl", label: "TTL", style: { width: 80 }, tdStyle: { fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", textAlign: "right" }, render: (r) => r.ttl || "-" },
        ]}
        rows={filtered}
      />
    </>
  );
}

/* ── Infrastructure Section (Tech + SSL + Headers) ───────────────────────── */
function InfraSection({ technologies, ssl_info, headers }) {
  const hasTech = technologies && Object.keys(technologies).length > 0;
  const hasSsl = ssl_info && Object.keys(ssl_info).length > 0;
  const hasHeaders = headers && Object.keys(headers).length > 0;

  if (!hasTech && !hasSsl && !hasHeaders) return <EmptyState message="No infrastructure data collected" />;

  return (
    <>
      {hasTech && (
        <div className="card" style={{ padding: 16, marginBottom: 16 }}>
          <SectionHeader title="Technology Stack" count={Object.values(technologies).flat().length} />
          {Object.entries(technologies).map(([host, techs]) => (
            <div key={host} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 6, fontFamily: "var(--mono)", fontWeight: 500 }}>{host}</div>
              <div className="pill-row">
                {(Array.isArray(techs) ? techs : []).map((t, i) => <Pill key={i}>{t}</Pill>)}
              </div>
            </div>
          ))}
        </div>
      )}

      {hasSsl && (
        <div className="card" style={{ padding: 16, marginBottom: 16 }}>
          <SectionHeader title="SSL / TLS" count={Object.keys(ssl_info).length} />
          {Object.entries(ssl_info).map(([host, info]) => (
            <div key={host} style={{ marginBottom: 16, paddingBottom: 16, borderBottom: "1px solid var(--border)" }}>
              <div style={{ fontSize: 13, color: "var(--accent)", marginBottom: 8, fontFamily: "var(--mono)", fontWeight: 500 }}>{host}</div>
              {info.protocols?.length > 0 && (
                <div style={{ marginBottom: 8 }}>
                  <span style={{ fontSize: 11, color: "var(--text-dim)", marginRight: 8 }}>Protocols:</span>
                  {info.protocols.map((p, i) => (
                    <Pill key={i} color={/SSLv[23]/.test(p) ? "var(--red)" : "var(--green)"}>{p}</Pill>
                  ))}
                </div>
              )}
              {info.certificate?.subject && (
                <div style={{ display: "grid", gridTemplateColumns: "80px 1fr", gap: "4px 12px", fontSize: 12, fontFamily: "var(--mono)" }}>
                  <span style={{ color: "var(--text-dim)" }}>Subject</span><span style={{ color: "var(--text-h)" }}>{info.certificate.subject}</span>
                  {info.certificate.issuer && <><span style={{ color: "var(--text-dim)" }}>Issuer</span><span>{info.certificate.issuer}</span></>}
                  {info.certificate.expires && <><span style={{ color: "var(--text-dim)" }}>Expires</span><span>{info.certificate.expires}</span></>}
                </div>
              )}
              {info.ciphers?.length > 0 && (
                <details style={{ marginTop: 8 }}>
                  <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--text-dim)" }}>{info.ciphers.length} ciphers</summary>
                  <div className="code-block" style={{ marginTop: 6, maxHeight: 200 }}>
                    {info.ciphers.map(c => `${c.protocol} ${c.bits}bit ${c.cipher} [${c.status}]`).join("\n")}
                  </div>
                </details>
              )}
            </div>
          ))}
        </div>
      )}

      {hasHeaders && (
        <div className="card" style={{ padding: 16 }}>
          <SectionHeader title="Security Headers" count={Object.keys(headers).length} />
          {Object.entries(headers).map(([host, hdrs]) => (
            <div key={host} style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: "var(--accent)", marginBottom: 8, fontFamily: "var(--mono)", fontWeight: 500 }}>{host}</div>
              {typeof hdrs === "object" && !Array.isArray(hdrs) ? (
                <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: "0" }}>
                  {Object.entries(hdrs).map(([k, v]) => (
                    <React.Fragment key={k}>
                      <div style={{ padding: "6px 0", fontSize: 12, fontFamily: "var(--mono)", fontWeight: 600, color: "var(--text-h)", borderBottom: "1px solid var(--border)" }}>{k}</div>
                      <div style={{ padding: "6px 0", fontSize: 12, fontFamily: "var(--mono)", color: "var(--text-dim)", borderBottom: "1px solid var(--border)", wordBreak: "break-all" }}>{String(v)}</div>
                    </React.Fragment>
                  ))}
                </div>
              ) : (
                <div className="code-block">{JSON.stringify(hdrs, null, 2)}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/* ── Secrets Section (Directories + Secrets) ─────────────────────────────── */
function SecretsSection({ directories, secrets }) {
  const hasDirs = directories?.length > 0;
  const hasSecrets = secrets?.length > 0;
  if (!hasDirs && !hasSecrets) return <EmptyState message="No secrets or directories discovered" />;

  return (
    <div className="two-col">
      {hasDirs && (
        <div className="card" style={{ padding: 16 }}>
          <SectionHeader title="Directories" count={directories.length} accent="var(--blue)" />
          <div style={{ maxHeight: 400, overflowY: "auto" }}>
            {directories.map((d, i) => {
              const txt = typeof d === "string" ? d : (d.path || d.name || d.url || JSON.stringify(d));
              return (
                <div key={i} style={{ padding: "6px 0", fontSize: 13, fontFamily: "var(--mono)", borderBottom: "1px solid var(--border)", color: "var(--text-h)" }}>{txt}</div>
              );
            })}
          </div>
        </div>
      )}

      {hasSecrets && (
        <div className="card" style={{ padding: 16, borderColor: "rgba(231,0,11,0.2)" }}>
          <SectionHeader title="Exposed Secrets" count={secrets.length} accent="var(--red)" />
          <div style={{ maxHeight: 400, overflowY: "auto" }}>
            {secrets.map((s, i) => {
              const txt = typeof s === "string" ? s : (s.path || s.name || s.value || JSON.stringify(s));
              return (
                <div key={i} style={{ padding: "6px 0", fontSize: 13, fontFamily: "var(--mono)", borderBottom: "1px solid var(--border)", color: "var(--red)" }}>{txt}</div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Requests Section ────────────────────────────────────────────────────── */
function RequestsSection({ requests }) {
  const [search, setSearch] = useState("");
  if (!requests?.length) return <EmptyState message="No captured requests" />;

  const filtered = search
    ? requests.filter(r => {
        const text = `${r.tool || r.method || ""} ${r.command || r.url || r.target || ""}`.toLowerCase();
        return text.includes(search.toLowerCase());
      })
    : requests;

  return (
    <>
      <div className="filter-bar">
        <input type="text" placeholder="Search requests..." value={search} onChange={e => setSearch(e.target.value)} style={{ minWidth: 240 }} />
        <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{filtered.length} of {requests.length} requests</span>
      </div>
      <DataTable
        maxHeight={500}
        columns={[
          { key: "tool", label: "Tool", style: { width: 100 }, render: (r) => {
            const ok = r.success !== false;
            return <span className={`badge ${ok ? "info" : "critical"}`} style={{ fontSize: 10 }}>{r.tool || r.method || "?"}</span>;
          }},
          { key: "target", label: "Command / Target", tdStyle: { fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-h)", wordBreak: "break-all" }, render: (r) => r.command || r.url || r.target || "?" },
          { key: "bytes", label: "Output", style: { width: 80 }, tdStyle: { fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)", textAlign: "right" }, render: (r) => {
            if (!r.stdout_bytes) return "-";
            return r.stdout_bytes > 1024 ? `${(r.stdout_bytes / 1024).toFixed(1)}K` : `${r.stdout_bytes}B`;
          }},
        ]}
        rows={filtered.slice(0, 200)}
      />
    </>
  );
}

/* ── Tool Results Section ────────────────────────────────────────────────── */
const TOOL_COLORS = {
  subfinder: "var(--cyan)", assetfinder: "var(--cyan)", amass: "var(--cyan)",
  httpx: "var(--green)", whatweb: "var(--orange)", wafw00f: "var(--red)",
  nmap: "var(--purple)", masscan: "var(--purple)", nuclei: "var(--red)",
  dig: "var(--blue)", nikto: "var(--yellow)", sslscan: "var(--accent)",
  katana: "var(--green)", ffuf: "var(--orange)", curl: "var(--text-dim)",
  dnsenum: "var(--blue)", fierce: "var(--blue)", whois: "var(--blue)",
};

function ToolResultsSection({ scanId, toolExecutions }) {
  const [expanded, setExpanded] = useState({});
  const [expandedTargets, setExpandedTargets] = useState({});
  const [toolOutputs, setToolOutputs] = useState(null);
  const execs = toolExecutions || [];

  useEffect(() => {
    if (!scanId) return;
    fetch(`/api/scans/${scanId}/tool-outputs?grouped=true`)
      .then(r => r.json())
      .then(setToolOutputs)
      .catch(() => setToolOutputs([]));
  }, [scanId]);

  const toolStats = {};
  execs.forEach(e => {
    if (!e?.tool) return;
    if (!toolStats[e.tool]) toolStats[e.tool] = { runs: 0, success: 0, targets: new Set() };
    toolStats[e.tool].runs++;
    if (e.success) toolStats[e.tool].success++;
    if (e.target) toolStats[e.tool].targets.add(e.target);
  });

  if (toolOutputs === null) return <div style={{ fontSize: 13, color: "var(--text-dim)" }}>Loading tool outputs...</div>;
  if (!toolOutputs.length && !Object.keys(toolStats).length) return <EmptyState message="No tool results yet. Tool results will appear here as each recon tool completes." />;

  const toggleTool = (t) => setExpanded(prev => ({ ...prev, [t]: !prev[t] }));
  const toggleTarget = (key) => setExpandedTargets(prev => ({ ...prev, [key]: !prev[key] }));

  const totalTools = toolOutputs.length || Object.keys(toolStats).length;

  return (
    <>
      <div style={{ marginBottom: 16, fontSize: 13, color: "var(--text-dim)" }}>
        {totalTools} tools used &middot; {execs.length} total executions
      </div>
      {toolOutputs.map(({ tool, targets }) => {
        const stats = toolStats[tool] || { runs: 0, success: 0, targets: new Set() };
        const color = TOOL_COLORS[tool] || "var(--accent)";
        const targetCount = Object.keys(targets || {}).length;
        const isOpen = expanded[tool];

        return (
          <div key={tool} className="card" style={{ padding: 0, marginBottom: 12, overflow: "hidden" }}>
            <div
              onClick={() => toggleTool(tool)}
              style={{
                padding: "12px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12,
                background: isOpen ? "rgba(255,255,255,0.03)" : "transparent",
              }}
            >
              <span style={{ color, fontWeight: 700, fontFamily: "var(--mono)", fontSize: 14, minWidth: 100 }}>
                {tool}
              </span>
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                {stats.runs} run{stats.runs !== 1 ? "s" : ""} &middot; {stats.success}/{stats.runs} success
              </span>
              <Pill>{targetCount} target{targetCount !== 1 ? "s" : ""}</Pill>
              <span style={{ marginLeft: "auto", fontSize: 11, opacity: 0.4 }}>{isOpen ? "▲" : "▼"}</span>
            </div>

            {isOpen && targets && (
              <div style={{ padding: "0 16px 16px", borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                {Object.entries(targets).map(([target, runs]) => {
                  const tKey = `${tool}:${target}`;
                  const tOpen = expandedTargets[tKey];
                  return (
                    <div key={target} style={{ marginTop: 8, border: "1px solid rgba(255,255,255,0.06)", borderRadius: 6 }}>
                      <div
                        onClick={() => toggleTarget(tKey)}
                        style={{
                          padding: "8px 12px", cursor: "pointer", display: "flex", alignItems: "center", gap: 8,
                          background: tOpen ? "rgba(255,255,255,0.02)" : "transparent",
                        }}
                      >
                        <span style={{ fontSize: 12, fontFamily: "var(--mono)", color: "var(--text)" }}>{target}</span>
                        <span style={{ fontSize: 11, color: "var(--text-dim)" }}>{runs.length} run{runs.length !== 1 ? "s" : ""}</span>
                        <span style={{ marginLeft: "auto", fontSize: 11, opacity: 0.4 }}>{tOpen ? "▲" : "▼"}</span>
                      </div>
                      {tOpen && runs.map((run, i) => (
                        <div key={i} style={{ padding: "8px 12px", borderTop: "1px solid rgba(255,255,255,0.04)" }}>
                          <div style={{ fontSize: 11, color: "var(--text-dim)", marginBottom: 4, fontFamily: "var(--mono)" }}>
                            $ {run.command}
                          </div>
                          <pre style={{
                            fontSize: 11, lineHeight: 1.5, color: "var(--text)", background: "rgba(0,0,0,0.3)",
                            padding: 8, borderRadius: 4, overflow: "auto", maxHeight: 300, whiteSpace: "pre-wrap",
                            wordBreak: "break-all", margin: 0,
                          }}>
                            {run.stdout || "(no output)"}
                          </pre>
                          {run.exit_code !== 0 && run.exit_code !== -1 && (
                            <div style={{ fontSize: 11, color: "var(--red)", marginTop: 4 }}>Exit code: {run.exit_code}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </>
  );
}

/* ── Main ReconPanel ─────────────────────────────────────────────────────── */
export default function ReconPanel({ context, scanId }) {
  const [section, setSection] = useState("overview");

  if (!context) return <div className="empty">No recon data collected yet</div>;

  const hasAnything = context.subdomains?.length || context.endpoints?.length || context.ports?.length ||
    (context.technologies && Object.keys(context.technologies).length) ||
    context.osint || context.ssl_info || context.headers ||
    context.directories?.length || context.secrets?.length || context.captured_requests?.length ||
    context.dns_records?.length || context.tool_results || context.tool_executions?.length;

  if (!hasAnything) return <div className="empty">No recon data collected yet</div>;

  const sectionCounts = {
    subdomains: count(context.subdomains),
    endpoints: count(context.endpoints),
    ports: count(context.ports),
    dns: count(context.dns_records),
    osint: count(context.osint?.findings) + count(context.osint?.employees) + count(context.osint?.leaked_credentials),
    infra: count(context.technologies) + count(context.ssl_info) + count(context.headers),
    secrets: count(context.directories) + count(context.secrets),
    requests: count(context.captured_requests),
    tools: count(context.tool_executions),
  };

  return (
    <>
      <div className="tabs" style={{ marginBottom: 20 }}>
        {SECTIONS.map(s => (
          <button key={s.key} className={`tab ${section === s.key ? "active" : ""}`} onClick={() => setSection(s.key)}>
            {s.label}
            {sectionCounts[s.key] > 0 && <span style={{ marginLeft: 4, fontSize: 11, opacity: 0.5 }}>({sectionCounts[s.key]})</span>}
          </button>
        ))}
      </div>

      {section === "overview" && <OverviewSection context={context} />}
      {section === "subdomains" && <SubdomainsSection subdomains={context.subdomains} summary={context.subdomain_summary} />}
      {section === "endpoints" && <EndpointsSection endpoints={context.endpoints} />}
      {section === "ports" && <PortsSection ports={context.ports} />}
      {section === "dns" && <DnsSection records={context.dns_records} />}
      {section === "osint" && <OsintSection osint={context.osint} />}
      {section === "infra" && <InfraSection technologies={context.technologies} ssl_info={context.ssl_info} headers={context.headers} />}
      {section === "secrets" && <SecretsSection directories={context.directories} secrets={context.secrets} />}
      {section === "requests" && <RequestsSection requests={context.captured_requests} />}
      {section === "tools" && <ToolResultsSection scanId={scanId} toolExecutions={context.tool_executions} />}
    </>
  );
}
