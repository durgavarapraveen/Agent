import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 5.1 — attack narratives / recordings for confirmed high/critical findings.
const SEV_COLOR = { critical: "var(--red, #ff3355)", high: "#ff8800", medium: "#ffaa00", low: "#88bbff" };

export default function AttackRecordingsPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getAttackRecordings(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading recordings…</div>;

  const recordings = data?.recordings || [];

  if (recordings.length === 0) {
    return (
      <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
        No attack narratives yet. These are recorded for confirmed high/critical findings —
        step-by-step reproduction with request/response and (when available) a Playwright video.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {recordings.map((r, i) => {
        const color = SEV_COLOR[(r.severity || "").toLowerCase()] || "var(--text-dim)";
        return (
          <div key={i} style={{ border: `1px solid ${color}`, borderRadius: 6, padding: 16, background: "var(--bg-elev)" }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
              <span style={{ padding: "3px 10px", borderRadius: 3, fontSize: 11, fontWeight: 700, background: color, color: "#000" }}>
                {(r.severity || "?").toUpperCase()}
              </span>
              <span style={{ fontWeight: 700, color: "var(--text-h)" }}>{r.title}</span>
            </div>
            {r.video_path && (
              <video controls src={api.getEvidenceUrl(String(r.video_path).split(/[/\\]/).pop())}
                     style={{ maxWidth: "100%", borderRadius: 6, marginBottom: 10, border: "1px solid var(--border)" }} />
            )}
            <ol style={{ margin: 0, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 6 }}>
              {(r.steps || []).map((s, j) => (
                <li key={j} style={{ fontSize: 13, color: "var(--text)", lineHeight: 1.5 }}>
                  <span style={{ fontWeight: 600 }}>{s.action}</span>
                  {s.method ? ` ${s.method}` : ""} {s.url}
                  {s.note && <span style={{ color: "var(--text-dim)" }}> — {s.note}</span>}
                  {s.screenshot && (
                    <div style={{ marginTop: 6 }}>
                      <img src={api.getEvidenceUrl(String(s.screenshot).split(/[/\\]/).pop())}
                           alt={`step ${j + 1}`} style={{ maxWidth: "100%", borderRadius: 4, border: "1px solid var(--border)" }}
                           onError={(e) => { e.target.style.display = "none"; }} />
                    </div>
                  )}
                </li>
              ))}
            </ol>
          </div>
        );
      })}
    </div>
  );
}
