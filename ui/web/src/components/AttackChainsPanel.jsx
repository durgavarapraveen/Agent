import { useEffect, useState } from "react";
import { api } from "../api";

export default function AttackChainsPanel({ scanId }) {
  const [chains, setChains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api.getAttackChains(scanId).then((r) => {
      setChains(r.chains || []);
      setLoading(false);
    });
  };
  useEffect(() => { load(); }, [scanId]);

  const regen = async () => {
    setBusy(true);
    try { await api.regenerateAttackChains(scanId); load(); }
    finally { setBusy(false); }
  };

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading chains…</div>;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
        <span style={{ fontWeight: 700, letterSpacing: 1 }}>
          {chains.length} ATTACK CHAIN{chains.length === 1 ? "" : "S"}
        </span>
        <button className="btn btn-sm" onClick={regen} disabled={busy}
          style={{ marginLeft: "auto" }}>
          {busy ? "Regenerating…" : "Regenerate via LLM"}
        </button>
      </div>
      {chains.length === 0 && (
        <div style={{ padding: 20, border: "1px dashed var(--border)",
                       borderRadius: 8, color: "var(--text-dim)" }}>
          No attack chains synthesised yet. Chains compose after the scan completes,
          or trigger "Regenerate" above.
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {chains.map((ch, i) => <ChainCard key={i} chain={ch} />)}
      </div>
    </div>
  );
}

const SEV_COLOR = {
  CRITICAL: "var(--red, #ff3355)",
  HIGH: "#ff8800",
  MEDIUM: "#ffaa00",
  LOW: "#88bbff",
};

function ChainCard({ chain }) {
  const color = SEV_COLOR[(chain.severity || "").toUpperCase()] || "var(--text-dim)";
  const steps = chain.steps || [];
  return (
    <div style={{
      border: `1px solid ${color}`, borderRadius: 6, padding: 16,
      background: "var(--bg-elev)",
    }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 8 }}>
        <span style={{
          padding: "3px 10px", borderRadius: 3, fontSize: 11, fontWeight: 700,
          letterSpacing: 1, background: color, color: "#000",
        }}>{chain.severity || "?"}</span>
        <span style={{ fontWeight: 700, fontSize: 15, color: "var(--text-h)" }}>
          {chain.name || "Attack chain"}
        </span>
      </div>
      {chain.business_impact && (
        <div style={{ marginBottom: 12, color: "var(--red)", fontSize: 13, fontStyle: "italic" }}>
          Business impact: {chain.business_impact}
        </div>
      )}
      {chain.narrative && (
        <div style={{ marginBottom: 12, color: "var(--text)", fontSize: 13, lineHeight: 1.5 }}>
          {chain.narrative}
        </div>
      )}
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {steps.map((s, i) => (
          <div key={i} style={{
            display: "flex", gap: 10, alignItems: "baseline",
            padding: "6px 10px", borderLeft: `3px solid ${color}`,
            background: "var(--bg)",
          }}>
            <span style={{ fontFamily: "var(--mono)", color: color, fontWeight: 700, minWidth: 24 }}>
              {i + 1}
            </span>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, color: "var(--text-h)", fontSize: 13 }}>
                {s.vuln_title || s.action}
              </div>
              {s.vuln_location && (
                <div style={{ fontSize: 11, color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
                  {s.vuln_location}
                </div>
              )}
              {s.leads_to && (
                <div style={{ fontSize: 12, color: color, marginTop: 2 }}>
                  ↳ leads to: {s.leads_to}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
