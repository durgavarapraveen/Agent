import React, { useEffect, useState } from "react";
import { api } from "../api";

/**
 * Displays all `scan_artifacts` rows for a given scan.
 * Used from both the LiveScan (Artifacts / PoC tab) and the completed
 * ScanDetail (Artifacts tab) pages.
 */
export default function ArtifactsPanel({ scanId, poll = false }) {
  const [pocs, setPocs] = useState({});
  const [shots, setShots] = useState([]);
  const [others, setOthers] = useState([]);
  const [activeTab, setActiveTab] = useState("poc");
  const [selectedPoc, setSelectedPoc] = useState(null);

  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    const load = () => {
      api.getScanPocs(scanId).then(r => alive && setPocs(r.pocs || {})).catch(() => {});
      api.listScanScreenshots(scanId).then(r => alive && setShots(r.screenshots || [])).catch(() => {});
      api.listScanArtifacts(scanId).then(r => {
        if (!alive) return;
        setOthers((r.artifacts || []).filter(a =>
          !String(a.kind || "").startsWith("poc_") && a.kind !== "screenshot"));
      }).catch(() => {});
    };
    load();
    let iv = null;
    if (poll) iv = setInterval(load, 8000);
    return () => { alive = false; if (iv) clearInterval(iv); };
  }, [scanId, poll]);

  const pocKinds = Object.keys(pocs);

  useEffect(() => {
    if (!selectedPoc && pocKinds.length) setSelectedPoc(pocKinds[0]);
  }, [pocKinds, selectedPoc]);

  if (!pocKinds.length && !shots.length && !others.length) {
    return (
      <div className="empty">
        No artifacts stored yet — PoC scripts, screenshots, SARIF and canonical
        reports appear here once the scan reaches its reporting phase.
      </div>
    );
  }

  const subTabs = [
    { id: "poc", label: `PoC (${pocKinds.length})`, on: pocKinds.length > 0 },
    { id: "screenshots", label: `Screenshots (${shots.length})`, on: shots.length > 0 },
    { id: "others", label: `Other (${others.length})`, on: others.length > 0 },
  ].filter(t => t.on);
  // Reset activeTab if the current one no longer has content
  const activeIsValid = subTabs.some(t => t.id === activeTab);
  const currentTab = activeIsValid ? activeTab : (subTabs[0]?.id || "poc");

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 12, borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
        {subTabs.map(t => (
          <button key={t.id} className="btn btn-sm"
                  style={{ background: currentTab === t.id ? "var(--accent-purple)" : undefined,
                           color: currentTab === t.id ? "#fff" : undefined }}
                  onClick={() => setActiveTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {currentTab === "poc" && pocKinds.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: 12 }}>
          <div>
            {pocKinds.map(k => (
              <div key={k}
                   onClick={() => setSelectedPoc(k)}
                   style={{ padding: "6px 10px", cursor: "pointer",
                            background: selectedPoc === k ? "rgba(175,80,255,0.15)" : "transparent",
                            borderLeft: selectedPoc === k ? "3px solid var(--accent-purple)" : "3px solid transparent",
                            marginBottom: 4, fontFamily: "var(--mono)", fontSize: 12 }}>
                {pocs[k].name || k}
              </div>
            ))}
          </div>
          <div>
            {selectedPoc && pocs[selectedPoc] && (
              <div>
                <div className="flex-between" style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
                    {pocs[selectedPoc].mime_type} · {pocs[selectedPoc].size_bytes}B
                  </div>
                  <a className="btn btn-sm"
                     href={api.scanArtifactUrl(scanId, pocs[selectedPoc].id, true)}
                     download={pocs[selectedPoc].name}>Download</a>
                </div>
                <pre style={{ maxHeight: 500, overflow: "auto",
                              background: "var(--bg-alt)", padding: 12,
                              borderRadius: 4, fontSize: 12,
                              fontFamily: "var(--mono)",
                              whiteSpace: "pre-wrap" }}>
                  {pocs[selectedPoc].content}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {currentTab === "screenshots" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
          {shots.map(s => (
            <div key={s.id} style={{ border: "1px solid var(--border)", borderRadius: 4, padding: 8 }}>
              <a href={api.scanArtifactUrl(scanId, s.id)} target="_blank" rel="noopener noreferrer">
                <img src={api.scanArtifactUrl(scanId, s.id)}
                     alt={s.name}
                     style={{ width: "100%", height: 140, objectFit: "cover", borderRadius: 3 }} />
              </a>
              <div style={{ fontSize: 11, marginTop: 6, wordBreak: "break-all", color: "var(--text-dim)" }}>
                {s.metadata?.finding_title || s.name}
              </div>
              <div style={{ fontSize: 10, color: "var(--text-dim)" }}>
                {(s.size_bytes / 1024).toFixed(1)} KB
              </div>
            </div>
          ))}
        </div>
      )}

      {currentTab === "others" && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Kind</th><th>Name</th><th>Size</th><th>Created</th><th /></tr>
            </thead>
            <tbody>
              {others.map(a => (
                <tr key={a.id}>
                  <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{a.kind}</span></td>
                  <td>{a.name}</td>
                  <td>{(a.size_bytes / 1024).toFixed(1)} KB</td>
                  <td style={{ fontSize: 11 }}>{a.created_at}</td>
                  <td>
                    <a className="btn btn-sm"
                       href={api.scanArtifactUrl(scanId, a.id)}
                       target="_blank" rel="noopener noreferrer">View</a>{" "}
                    <a className="btn btn-sm"
                       href={api.scanArtifactUrl(scanId, a.id, true)}
                       download={a.name}>DL</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
