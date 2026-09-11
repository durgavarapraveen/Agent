import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 3.1 / 6.2 — attack-surface baseline diff (new/removed endpoints, param
// & JS changes, new subdomains) driving incremental re-scans.
export default function SurfaceDiffPanel({ scanId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api.getSurfaceDiff(scanId).then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading surface diff…</div>;

  if (!data?.has_baseline) {
    return (
      <div style={{ padding: 20, border: "1px dashed var(--border)", borderRadius: 8, color: "var(--text-dim)" }}>
        No stored attack-surface baseline for this target yet. After a full scan the surface
        (subdomains, endpoints, params, JS hashes) is persisted; the next scan diffs against it
        and re-tests only what changed (<code>--incremental</code>).
      </div>
    );
  }

  const diff = data.diff || {};
  const eps = diff.endpoints || {};
  const js = diff.js || {};
  const subs = diff.subdomains || {};
  const paramsChanged = diff.params_changed || {};

  const List = ({ title, items, color }) => (items && items.length > 0) ? (
    <div className="card" style={{ margin: "0 0 12px" }}>
      <h3 style={{ color }}>{title} ({items.length})</h3>
      <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", display: "flex", flexDirection: "column", gap: 3 }}>
        {items.map((x, i) => <div key={i}>{x}</div>)}
      </div>
    </div>
  ) : null;

  const nothing = !diff.has_changes;

  return (
    <div>
      <div style={{ marginBottom: 12, fontSize: 13, color: nothing ? "var(--green)" : "var(--text)" }}>
        {nothing ? "Attack surface unchanged since baseline." : "Attack surface changed since baseline:"}
      </div>
      <List title="New endpoints" items={eps.added} color="var(--red)" />
      <List title="Removed endpoints" items={eps.removed} color="var(--text-dim)" />
      <List title="New subdomains" items={subs.added} color="var(--orange)" />
      <List title="Changed JS bundles" items={js.changed} color="var(--yellow)" />
      <List title="New JS bundles" items={js.added} color="var(--yellow)" />
      {Object.keys(paramsChanged).length > 0 && (
        <div className="card" style={{ margin: "0 0 12px" }}>
          <h3 style={{ color: "var(--orange)" }}>Parameter changes ({Object.keys(paramsChanged).length})</h3>
          {Object.entries(paramsChanged).map(([ep, ch], i) => (
            <div key={i} style={{ marginBottom: 6, fontSize: 12 }}>
              <div style={{ fontFamily: "var(--mono)", color: "var(--text-h)" }}>{ep}</div>
              {ch.added?.length > 0 && <span style={{ color: "var(--green)" }}>+ {ch.added.join(", ")} </span>}
              {ch.removed?.length > 0 && <span style={{ color: "var(--red)" }}>− {ch.removed.join(", ")}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
