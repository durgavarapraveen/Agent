import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 5.2 — AI-generated fix code per finding.
export default function FixSuggestionsPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getFixSuggestions(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Generating fix suggestions…</div>;

  const fixes = data?.fixes || [];
  const stack = data?.stack || {};

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 14, alignItems: "baseline" }}>
        <span style={{ fontWeight: 700, letterSpacing: 1 }}>{fixes.length} FIX SUGGESTION{fixes.length === 1 ? "" : "S"}</span>
        {(stack.language || stack.framework) && (
          <span style={{ color: "var(--text-dim)", fontSize: 13 }}>
            detected stack: <span className="pill">{stack.language || "?"} / {stack.framework || "?"}</span>
          </span>
        )}
      </div>

      {fixes.length === 0 && (
        <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
          No fix suggestions available (need findings with a recognized vulnerability class).
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {fixes.map((f, i) => (
          <div key={i} className="card" style={{ margin: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span className={`badge ${(f.severity || "info").toLowerCase()}`}>{(f.severity || "").toUpperCase()}</span>
              <span style={{ fontWeight: 600, color: "var(--text-h)" }}>{f.finding}</span>
              <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-dim)" }}>
                {f.framework !== "unknown" ? f.framework : f.vuln_class} · {f.source}
              </span>
            </div>
            <pre style={{
              background: "#0d1117", color: "#c9d1d9", padding: 12, borderRadius: 6,
              fontSize: 12, fontFamily: "var(--mono)", lineHeight: 1.5, overflow: "auto",
              whiteSpace: "pre", margin: 0, maxHeight: 320,
            }}>{f.fix_code}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}
