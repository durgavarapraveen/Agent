import React, { useEffect, useState, useCallback } from "react";
import { api } from "../api";
import { fmtDate } from "../components/utils";

// Campaign engine (delta 5) — persistent, resumable, multi-target campaigns.
// Launch a campaign over a scoped estate; each target's scan state is persisted
// per-target in Postgres, so the run survives an API restart and can resume.

const STATUS_COLOR = {
  pending: "var(--text-dim)", running: "var(--blue)",
  completed: "var(--green, #3fb950)", failed: "var(--red)",
};

function TargetRow({ t }) {
  return (
    <tr>
      <td style={{ fontFamily: "var(--mono)", fontSize: 12, wordBreak: "break-all" }}>{t.target}</td>
      <td><span style={{ color: STATUS_COLOR[t.status] || "var(--text)", fontWeight: 600 }}>{t.status}</span></td>
      <td style={{ textAlign: "center" }}>{t.vuln_count}</td>
      <td style={{ textAlign: "center", color: "var(--red)" }}>{t.critical_count}</td>
      <td style={{ textAlign: "center", color: "var(--orange)" }}>{t.high_count}</td>
      <td style={{ textAlign: "center" }}>{t.exploit_count}</td>
      <td style={{ textAlign: "right" }}>{t.duration_seconds ? `${Math.round(t.duration_seconds)}s` : "—"}</td>
      <td style={{ fontSize: 11, color: "var(--red)", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" }}>{t.error || ""}</td>
    </tr>
  );
}

function CampaignCard({ campaign, onSelect, selected }) {
  const p = campaign.target_progress || {};
  return (
    <div className="card" style={{ margin: 0, cursor: "pointer", border: selected ? "1px solid var(--blue)" : undefined }}
         onClick={() => onSelect(campaign.campaign_id)}>
      <div className="flex-between">
        <div style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{campaign.campaign_id}</div>
        <span style={{ color: campaign.status === "running" ? "var(--blue)" : "var(--text-dim)", fontWeight: 600 }}>
          {campaign.status}
        </span>
      </div>
      <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
        tier {campaign.tier} · {campaign.total_targets} targets · {fmtDate(campaign.created_at)}
      </div>
      <div style={{ display: "flex", gap: 10, marginTop: 8, fontSize: 12 }}>
        <span style={{ color: STATUS_COLOR.completed }}>✓ {p.completed || 0}</span>
        <span style={{ color: STATUS_COLOR.running }}>▶ {p.running || 0}</span>
        <span style={{ color: STATUS_COLOR.pending }}>◔ {p.pending || 0}</span>
        <span style={{ color: STATUS_COLOR.failed }}>✕ {p.failed || 0}</span>
        <span style={{ marginLeft: "auto", color: "var(--orange)" }}>{p.vulns || 0} vulns</span>
      </div>
    </div>
  );
}

export default function Campaigns() {
  const [campaigns, setCampaigns] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [targets, setTargets] = useState("");
  const [tier, setTier] = useState("POC");
  const [maxParallel, setMaxParallel] = useState(3);
  const [msg, setMsg] = useState("");

  const refresh = useCallback(async () => {
    const list = await api.getCampaigns().catch(() => []);
    setCampaigns(Array.isArray(list) ? list : []);
    if (list && list.length && !selected) setSelected(list[0].campaign_id);
  }, [selected]);

  useEffect(() => { refresh(); const iv = setInterval(refresh, 3000); return () => clearInterval(iv); }, [refresh]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    let stop = false;
    const tick = async () => {
      const d = await api.getCampaign(selected).catch(() => null);
      if (!stop) setDetail(d);
    };
    tick();
    const iv = setInterval(tick, 2500);
    return () => { stop = true; clearInterval(iv); };
  }, [selected]);

  const launch = async () => {
    const list = targets.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
    if (!list.length) { setMsg("Enter at least one target URL."); return; }
    setMsg("Launching…");
    try {
      const r = await api.runCampaign({ targets: list, tier, max_parallel: Number(maxParallel) });
      setMsg(`Started campaign ${r.campaign_id} (${r.targets} targets)`);
      setSelected(r.campaign_id);
      setTargets("");
      refresh();
    } catch (e) { setMsg(`Launch failed: ${e.message || e}`); }
  };

  const resume = async (id) => {
    setMsg("Resuming…");
    try {
      const r = await api.resumeCampaign(id);
      setMsg(r.status === "resumed" ? `Resumed — ${r.remaining} targets remaining` : `Nothing to resume`);
      refresh();
    } catch (e) { setMsg(`Resume failed: ${e.message || e}`); }
  };

  const dp = detail?.target_progress || {};

  return (
    <div style={{ padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>Campaigns</h2>
      <p style={{ color: "var(--text-dim)", marginTop: -8 }}>
        Persistent, resumable multi-target campaigns over your scoped estate. Per-target state is
        saved to the database, so a campaign survives an API restart and can be resumed.
      </p>

      {/* Launch form */}
      <div className="card" style={{ margin: "12px 0" }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>New campaign</div>
        <textarea
          value={targets} onChange={e => setTargets(e.target.value)}
          placeholder="One target URL per line (or comma-separated). Authorized scope only."
          style={{ width: "100%", minHeight: 90, fontFamily: "var(--mono)", fontSize: 13,
                   background: "var(--bg-2,#14161c)", color: "var(--text)", border: "1px solid var(--border,#262a33)",
                   borderRadius: 8, padding: 10, boxSizing: "border-box" }}
        />
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
          <label>Tier{" "}
            <select value={tier} onChange={e => setTier(e.target.value)}>
              {["POC", "QUICK", "STANDARD", "DEEP"].map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label>Max parallel{" "}
            <input type="number" min={1} max={32} value={maxParallel}
                   onChange={e => setMaxParallel(e.target.value)} style={{ width: 60 }} />
          </label>
          <button className="btn" onClick={launch}>Launch campaign</button>
          {msg && <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{msg}</span>}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "320px 1fr", gap: 16, alignItems: "start" }}>
        {/* Campaign list */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {campaigns.length === 0
            ? <div className="card" style={{ margin: 0, color: "var(--text-dim)" }}>No campaigns yet.</div>
            : campaigns.map(c => (
                <CampaignCard key={c.campaign_id} campaign={c} selected={selected === c.campaign_id} onSelect={setSelected} />
              ))}
        </div>

        {/* Selected campaign detail */}
        <div className="card" style={{ margin: 0 }}>
          {!detail ? (
            <div style={{ color: "var(--text-dim)" }}>Select a campaign to see live per-target progress.</div>
          ) : (
            <>
              <div className="flex-between" style={{ marginBottom: 10 }}>
                <div>
                  <div style={{ fontWeight: 700, fontFamily: "var(--mono)" }}>{detail.campaign_id}</div>
                  <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
                    {detail.status} · tier {detail.tier} · {dp.completed || 0}/{dp.total || 0} done · {dp.vulns || 0} vulns
                  </div>
                </div>
                <button className="btn" onClick={() => resume(detail.campaign_id)}
                        disabled={(dp.pending || 0) + (dp.running || 0) === 0}>
                  Resume
                </button>
              </div>
              <div style={{ overflowX: "auto" }}>
                <table className="table" style={{ width: "100%" }}>
                  <thead><tr>
                    <th>Target</th><th>Status</th><th>Vulns</th><th>Crit</th><th>High</th><th>Exploits</th><th>Time</th><th>Error</th>
                  </tr></thead>
                  <tbody>
                    {(detail.targets || []).map(t => <TargetRow key={t.target} t={t} />)}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
