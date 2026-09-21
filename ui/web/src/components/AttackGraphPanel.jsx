import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";

// Attack graph (B1) — live node/edge render of the exploitation graph.
// Nodes = vulnerabilities (colored by severity, ringed when exploited),
// edges = relationships (credentials_from / escalates_to / access_to ...).
// Circular deterministic layout (no physics dep); polls while the scan runs.

const SEV_COLOR = {
  critical: "#f85149", high: "#ff7b28", medium: "#d29922", low: "#3fb950", info: "#8b949e",
};
const sevColor = (s) => SEV_COLOR[String(s || "").toLowerCase()] || "#8b949e";

export default function AttackGraphPanel({ scanId, poll = false }) {
  const [graph, setGraph] = useState({ nodes: [], edges: [], exploited_count: 0 });
  const [hover, setHover] = useState(null);
  const stopRef = useRef(false);

  useEffect(() => {
    stopRef.current = false;
    const tick = async () => {
      const g = await api.getAttackGraph(scanId);
      if (!stopRef.current) setGraph(g);
    };
    tick();
    let iv = null;
    if (poll) iv = setInterval(tick, 3000);
    return () => { stopRef.current = true; if (iv) clearInterval(iv); };
  }, [scanId, poll]);

  const nodes = graph.nodes || [];
  const edges = graph.edges || [];

  const W = 720, H = 520, cx = W / 2, cy = H / 2;
  const R = Math.min(cx, cy) - 70;
  const pos = {};
  nodes.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(nodes.length, 1) - Math.PI / 2;
    pos[n.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
  });

  return (
    <div className="card" style={{ margin: 0 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-h)" }}>Attack Graph</div>
          <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
            Vulnerabilities as nodes, exploit relationships as edges — exploited nodes are ringed
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 12, color: "var(--text-dim)" }}>
          <span><b style={{ color: "var(--text-h)" }}>{graph.node_count || nodes.length}</b> nodes</span>
          <span><b style={{ color: "var(--text-h)" }}>{graph.edge_count || edges.length}</b> edges</span>
          <span><b style={{ color: "#f85149" }}>{graph.exploited_count || 0}</b> exploited</span>
        </div>
      </div>

      {nodes.length === 0 ? (
        <div style={{ padding: 24, textAlign: "center", color: "var(--text-dim)", fontSize: 13 }}>
          No attack graph yet — it is built during the exploitation/chaining phase from confirmed findings.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", maxWidth: W, background: "var(--bg-2,#0f1116)", borderRadius: 8 }}>
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill="#57606a" />
              </marker>
            </defs>
            {edges.map((e, i) => {
              const s = pos[e.source], t = pos[e.target];
              if (!s || !t) return null;
              const mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
              return (
                <g key={i}>
                  <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="#57606a"
                        strokeWidth={0.5 + (e.success_rate || 0.5) * 2} markerEnd="url(#arrow)" opacity={0.7} />
                  {hover === null && edges.length <= 14 && (
                    <text x={mx} y={my - 2} fontSize="8" fill="#8b949e" textAnchor="middle">{e.relationship}</text>
                  )}
                </g>
              );
            })}
            {nodes.map((n) => {
              const p = pos[n.id];
              if (!p) return null;
              const c = sevColor(n.severity);
              return (
                <g key={n.id} onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} style={{ cursor: "pointer" }}>
                  {n.exploited && <circle cx={p.x} cy={p.y} r={16} fill="none" stroke="#f85149" strokeWidth={2} strokeDasharray="3 2" />}
                  <circle cx={p.x} cy={p.y} r={10} fill={c} stroke="#0f1116" strokeWidth={1.5} />
                  <text x={p.x} y={p.y + 24} fontSize="9" fill="var(--text-dim,#8b949e)" textAnchor="middle">
                    {n.type}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      )}

      {hover && (() => {
        const n = nodes.find(x => x.id === hover);
        if (!n) return null;
        return (
          <div style={{ marginTop: 8, padding: 8, background: "var(--bg-2,#14161c)", borderRadius: 6, fontSize: 12 }}>
            <b style={{ color: sevColor(n.severity) }}>{n.type}</b>{" "}
            <span style={{ color: "var(--text-dim)" }}>[{n.severity}]</span>{" "}
            {n.exploited && <span style={{ color: "#f85149" }}>· EXPLOITED</span>}
            <div style={{ fontFamily: "var(--mono)", color: "var(--text-dim)", wordBreak: "break-all" }}>{n.location}</div>
            {n.title && <div style={{ color: "var(--text)" }}>{n.title}</div>}
          </div>
        );
      })()}
    </div>
  );
}
