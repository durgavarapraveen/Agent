import { useEffect, useState } from "react";
import { api } from "../api";

export default function ScanDiffPanel({ scanId }) {
  const [scans, setScans] = useState([]);
  const [baseline, setBaseline] = useState("");
  const [diff, setDiff] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getScans?.().then((rows) => setScans(rows || [])).catch(() => {});
  }, []);

  const runDiff = async (bId) => {
    if (!bId) return;
    setBusy(true); setDiff(null);
    try { setDiff(await api.diffScans(scanId, bId)); }
    catch (e) { setDiff({ error: String(e.message || e) }); }
    finally { setBusy(false); }
  };

  const others = (scans || []).filter((s) => s.scan_id && s.scan_id !== scanId);

  return (
    <div>
      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 14 }}>
        <span style={{ color: "var(--text-dim)", fontSize: 13 }}>Compare against baseline scan:</span>
        <select value={baseline} onChange={(e) => { setBaseline(e.target.value); runDiff(e.target.value); }}
          disabled={busy}
          style={{ padding: "6px 10px", background: "var(--bg-elev)",
                    color: "var(--text-h)", border: "1px solid var(--border)",
                    borderRadius: 4, fontFamily: "var(--mono)", fontSize: 12, minWidth: 400 }}>
          <option value="">— pick a scan —</option>
          {others.map((s) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.target} · {new Date(s.started_at).toLocaleString()}
            </option>
          ))}
        </select>
      </div>
      {busy && <div style={{ color: "var(--text-dim)" }}>Computing diff…</div>}
      {diff && !diff.error && <DiffView diff={diff} />}
      {diff?.error && <div style={{ color: "var(--red)" }}>{diff.error}</div>}
    </div>
  );
}

function DiffView({ diff }) {
  const s = diff.summary || {};
  return (
    <div>
      <div style={{ display: "flex", gap: 14, marginBottom: 16 }}>
        <Stat label="New" value={s.new} color="var(--red)" />
        <Stat label="Resolved" value={s.resolved} color="var(--accent, #00ff9a)" />
        <Stat label="Regressed" value={s.regressed} color="#ff8800" />
        <Stat label="Unchanged" value={s.unchanged} color="var(--text-dim)" />
      </div>
      <Bucket title="🔴 New (regressions/new attack surface)" rows={diff.new} color="var(--red)" />
      <Bucket title="🟢 Resolved" rows={diff.resolved} color="var(--accent, #00ff9a)" />
      {diff.regressed?.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontWeight: 700, letterSpacing: 1, marginBottom: 8, color: "#ff8800" }}>
            🟠 REGRESSED (severity elevated)
          </div>
          {diff.regressed.map((r, i) => (
            <div key={i} style={{ padding: 10, border: "1px solid #ff8800",
                                   borderRadius: 4, marginBottom: 6, background: "var(--bg-elev)" }}>
              <div style={{ color: "var(--text-h)", fontWeight: 600 }}>{r.after.title}</div>
              <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
                {r.before.severity} → <b style={{ color: "#ff8800" }}>{r.after.severity}</b> · {r.after.location}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{ flex: 1, textAlign: "center", padding: 12,
                   border: `1px solid ${color}`, borderRadius: 4 }}>
      <div style={{ fontSize: 24, fontWeight: 700, color, fontFamily: "var(--mono)" }}>{value ?? 0}</div>
      <div style={{ fontSize: 11, color: "var(--text-dim)", letterSpacing: 1 }}>{label}</div>
    </div>
  );
}

function Bucket({ title, rows, color }) {
  if (!rows?.length) return null;
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontWeight: 700, letterSpacing: 1, marginBottom: 8, color }}>{title}</div>
      {rows.map((v, i) => (
        <div key={i} style={{ padding: 8, borderLeft: `3px solid ${color}`,
                               marginBottom: 4, background: "var(--bg-elev)" }}>
          <div style={{ color: "var(--text-h)", fontSize: 13, fontWeight: 600 }}>{v.title}</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
            [{v.severity}] {v.location}
          </div>
        </div>
      ))}
    </div>
  );
}
