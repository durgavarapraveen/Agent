import { useEffect, useState } from "react";
import { api } from "../api";

/**
 * Access Gained — every successful auth bypass / login captured during a scan.
 * Shows: technique badge, the exact payload that worked, JWT preview, decoded
 * role, and a short response snippet as proof-of-entry.
 *
 * Used in both LiveScan (with poll=true) and ScanDetail (no polling).
 */
export default function AccessGainedPanel({ scanId, poll = false }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    const load = () => {
      api.getAuthBypasses(scanId).then((r) => {
        if (!cancelled) {
          setRows(r.bypasses || []);
          setLoading(false);
        }
      });
    };
    load();
    if (!poll) return () => { cancelled = true; };
    const iv = setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(iv); };
  }, [scanId, poll]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading access events…</div>;
  if (!rows.length) {
    return (
      <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
        No auth bypass or successful login captured yet.
      </div>
    );
  }

  return (
    <div>
      <div style={{
        display: "flex", alignItems: "center", gap: 12, marginBottom: 12,
        padding: "10px 14px", background: "rgba(255,51,85,0.08)",
        border: "1px solid var(--red)", borderRadius: 6,
      }}>
        <span style={{ fontSize: 20 }}>◉</span>
        <span style={{ fontWeight: 700, letterSpacing: 1, color: "var(--red)" }}>
          ACCESS GAINED — {rows.length} session{rows.length === 1 ? "" : "s"} obtained
        </span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {rows.map((r) => <BypassCard key={r.id} row={r} />)}
      </div>
    </div>
  );
}

const TECH_META = {
  sqli_bypass:       { label: "SQL Injection Bypass",   color: "#ff3355" },
  mass_assign_admin: { label: "Mass Assignment (admin)", color: "#ff8800" },
  self_register:     { label: "Self-Registration",       color: "#ffaa00" },
  credential_replay: { label: "Credential Replay",       color: "#00ff9a" },
  default_creds:     { label: "Default Credentials",     color: "#ff3355" },
  sqlmap_dump:       { label: "sqlmap DB Dump",          color: "#ff3355" },
  hash_crack:        { label: "Cracked Password Hash",   color: "#ff8800" },
};

function BypassCard({ row }) {
  const meta = TECH_META[row.technique] || { label: row.technique, color: "#888" };
  const roleAdmin = /admin|root|superuser/i.test(row.role || "");
  return (
    <div style={{
      border: "1px solid var(--border)", borderRadius: 6, padding: 14,
      background: "var(--bg-elev)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
        <span style={{
          padding: "3px 10px", borderRadius: 3, fontSize: 11, fontWeight: 700,
          letterSpacing: 1, background: meta.color, color: "#000",
        }}>{meta.label}</span>
        {row.role && (
          <span style={{
            padding: "3px 10px", borderRadius: 3, fontSize: 11, fontWeight: 700, letterSpacing: 1,
            background: roleAdmin ? "var(--red)" : "var(--text-dim)", color: "#000",
          }}>role: {row.role}</span>
        )}
        <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 12 }}>
          {row.method} {row.login_url}
        </span>
        <span style={{ marginLeft: "auto", color: "var(--text-dim)", fontSize: 12 }}>
          HTTP {row.response_status}
        </span>
      </div>

      <Row label="User"     value={row.username || "—"} mono />
      {row.password && <Row label="Password" value={row.password} mono />}
      {row.payload && <RowMulti label="Payload sent" value={row.payload} />}
      {row.token_preview && (
        <Row label={`Token (${row.token_len} chars)`} value={row.token_preview + "  …"} mono />
      )}
      {row.response_snippet && <RowMulti label="Proof (response)" value={row.response_snippet} />}
      <div style={{ marginTop: 8, color: "var(--text-dim)", fontSize: 11 }}>
        {new Date(row.created_at).toLocaleString()}
      </div>
    </div>
  );
}

function Row({ label, value, mono }) {
  return (
    <div style={{ display: "flex", gap: 10, alignItems: "baseline", marginBottom: 4 }}>
      <span style={{ minWidth: 130, color: "var(--text-dim)", fontSize: 12 }}>{label}</span>
      <span style={{
        fontFamily: mono ? "var(--mono)" : "inherit", fontSize: 13,
        color: "var(--text-h)", wordBreak: "break-all",
      }}>{value}</span>
    </div>
  );
}

function RowMulti({ label, value }) {
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ color: "var(--text-dim)", fontSize: 12, marginBottom: 3 }}>{label}</div>
      <pre style={{
        margin: 0, padding: "8px 10px", background: "var(--bg-code, #0b0e10)",
        border: "1px solid var(--border)", borderRadius: 4,
        fontFamily: "var(--mono)", fontSize: 12, color: "var(--text-h)",
        whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 160, overflow: "auto",
      }}>{value}</pre>
    </div>
  );
}
