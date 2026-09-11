import { useEffect, useState } from "react";
import { api } from "../api";

// Phase 11 — benchmark catalogs (Juice Shop / DVWA) + token-budget target.
export default function Benchmarks() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [catFilter, setCatFilter] = useState("ALL");

  useEffect(() => {
    let alive = true;
    api.getBenchmarks().then((d) => { if (alive) setData(d); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  if (loading) return <div className="loading">Loading benchmarks…</div>;

  const js = data?.juice_shop || {};
  const dvwa = data?.dvwa || {};
  const challenges = js.challenges || [];
  const cats = ["ALL", ...(js.categories || [])];
  const filtered = catFilter === "ALL" ? challenges : challenges.filter((c) => c.category === catFilter);

  return (
    <div>
      <h1>Benchmarks</h1>
      <p style={{ color: "var(--text-dim)", fontSize: 13, marginTop: -8 }}>
        Validation suites the scanner is scored against. Live scores are produced in CI
        (weekly) against disposable Juice Shop / DVWA containers.
      </p>

      <div className="card-grid" style={{ marginTop: 12 }}>
        <div className="stat-card">
          <span className="label">Juice Shop Challenges</span>
          <span className="value">{js.total || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">DVWA Cases</span>
          <span className="value">{dvwa.cases || 0}</span>
        </div>
        <div className="stat-card">
          <span className="label">DVWA Levels</span>
          <span className="value" style={{ fontSize: 16 }}>{(dvwa.levels || []).join(", ") || "-"}</span>
        </div>
        <div className="stat-card">
          <span className="label">Token Budget Target</span>
          <span className="value" style={{ fontSize: 18 }}>
            {data?.token_budget_limit ? `< ${(data.token_budget_limit / 1_000_000).toFixed(0)}M` : "-"}
          </span>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
          {cats.map((c) => (
            <button key={c} onClick={() => setCatFilter(c)} className="btn btn-sm"
              style={{ background: catFilter === c ? "var(--accent)" : "var(--bg)",
                       color: catFilter === c ? "#fff" : "var(--text-dim)" }}>
              {c === "ALL" ? "All" : c}
            </button>
          ))}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Challenge</th><th>Category</th><th>Difficulty</th><th>Expected Executor</th></tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr key={c.id}>
                  <td style={{ color: "var(--text-h)" }}>{c.name}</td>
                  <td style={{ fontSize: 12 }}>{c.category}</td>
                  <td style={{ fontFamily: "var(--mono)" }}>{"★".repeat(c.difficulty || 1)}</td>
                  <td style={{ fontSize: 12, fontFamily: "var(--mono)", color: "var(--accent)" }}>{c.executor}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
