import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 6.1 (LLM cost) + Phase 5.3 (executive dollar risk).
export default function CostRiskPanel({ scanId }) {
  const [cost, setCost] = useState(null);
  const [routing, setRouting] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    Promise.all([api.getScanCost(scanId), api.getModelRoles()])
      .then(([c, mr]) => { if (alive) { setCost(c); setRouting(mr); } })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [scanId]);

  // Map a "provider/model" cost key to its known per-1M rate (substring match).
  const rateFor = (modelKey) => {
    const p = routing?.pricing || {};
    const id = String(modelKey).split("/").pop().toLowerCase();
    let hit = null;
    for (const [m, v] of Object.entries(p)) {
      if (id.includes(String(m).toLowerCase())) hit = v;
    }
    return hit;
  };

  if (loading) return <div style={{ color: "var(--text-dim)", padding: 16 }}>Loading LLM cost…</div>;

  const usd4 = (n) => "$" + Number(n || 0).toFixed(4);

  return (
    <div>
      {/* LLM cost */}
      <div className="card">
        <h3>LLM Cost (this scan)</h3>
        <div className="card-grid">
          <div className="stat-card">
            <span className="label">Total Cost</span>
            <span className="value">{usd4(cost?.total_cost_usd)}</span>
          </div>
          <div className="stat-card">
            <span className="label">Requests</span>
            <span className="value">{cost?.requests || 0}</span>
          </div>
          <div className="stat-card">
            <span className="label">Input Tokens</span>
            <span className="value" style={{ fontSize: 18 }}>{(cost?.total_input_tokens || 0).toLocaleString()}</span>
          </div>
          <div className="stat-card">
            <span className="label">Output Tokens</span>
            <span className="value" style={{ fontSize: 18 }}>{(cost?.total_output_tokens || 0).toLocaleString()}</span>
          </div>
        </div>
        {cost?.by_model && Object.keys(cost.by_model).length > 0 && (
          <div className="table-wrap" style={{ marginTop: 12 }}>
            <table>
              <thead>
                <tr>
                  <th>Provider / Model</th>
                  <th style={{ textAlign: "right" }}>Requests</th>
                  <th style={{ textAlign: "right" }}>Input tok</th>
                  <th style={{ textAlign: "right" }}>Output tok</th>
                  <th style={{ textAlign: "right" }}>Rate $/1M (in / out)</th>
                  <th style={{ textAlign: "right" }}>Cost</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(cost.by_model).map(([model, v]) => {
                  const rate = rateFor(model);
                  const unknown = rate && rate.known === false;
                  return (
                    <tr key={model}>
                      <td style={{ color: "var(--text-h)", fontFamily: "var(--mono)" }}>
                        {model}
                        {unknown && (
                          <span className="badge low" title="No known rate — cost shown as $0. Set LLM_PRICING_JSON."
                            style={{ marginLeft: 8 }}>no price</span>
                        )}
                      </td>
                      <td style={{ textAlign: "right" }}>{v.requests}</td>
                      <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>{(v.input_tokens || 0).toLocaleString()}</td>
                      <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>{(v.output_tokens || 0).toLocaleString()}</td>
                      <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>
                        {rate ? `$${rate.input_per_1m} / $${rate.output_per_1m}` : "—"}
                      </td>
                      <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>{usd4(v.cost_usd)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {(!cost || cost.requests === 0) && (
          <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>
            No per-scan LLM cost recorded yet (populates as the scan makes model calls).
          </div>
        )}
      </div>

      {/* Model routing: which model handles which task role */}
      {routing?.roles?.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>Model Routing</h3>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
            <span className={`badge ${routing?.zdr?.zdr_required ? "info" : "low"}`}>
              {routing?.zdr?.zdr_required ? "ZDR ON" : "ZDR OFF"}
            </span>
            {routing?.zdr?.zdr_required && (
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                data_retention=“{routing.zdr.data_retention || "none"}” · prompt/response content not stored
              </span>
            )}
            {routing?.allowlist?.length > 0 && (
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                · allowlist: {routing.allowlist.join(", ")}
              </span>
            )}
          </div>
          <div style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>
            Tasks are routed to different Bedrock models by role — cheap work to a fast model,
            hard reasoning to a strong one. Fallback = using the small/large default (set the
            role's env var to override). Routing is restricted to accessible models only.
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Role</th><th>Model</th><th>Source</th><th>Access</th>
                  <th style={{ textAlign: "right" }}>Rate $/1M (in / out)</th>
                </tr>
              </thead>
              <tbody>
                {routing.roles.map((r) => {
                  const rate = routing.pricing?.[r.model];
                  return (
                    <tr key={r.role}>
                      <td style={{ color: "var(--text-h)", textTransform: "capitalize" }}>{r.role}</td>
                      <td style={{ fontFamily: "var(--mono)" }}>{r.model || "—"}</td>
                      <td>
                        {r.downgraded ? (
                          <span className="badge critical"
                            title={`Configured model "${r.wanted}" is not accessible — swapped to "${r.model}". Add it to AWS_BEDROCK_ALLOWED_MODELS to keep it.`}>
                            downgraded
                          </span>
                        ) : (
                          <span className={`badge ${r.configured ? "info" : "low"}`}>
                            {r.configured ? "configured" : "fallback"}
                          </span>
                        )}
                      </td>
                      <td>
                        <span className={`badge ${r.accessible ? "info" : "critical"}`}>
                          {r.accessible ? "accessible" : "blocked"}
                        </span>
                      </td>
                      <td style={{ textAlign: "right", fontFamily: "var(--mono)" }}>
                        {rate ? (rate.known ? `$${rate.input_per_1m} / $${rate.output_per_1m}` : "no price") : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
