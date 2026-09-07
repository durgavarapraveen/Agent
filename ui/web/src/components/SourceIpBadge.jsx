import React, { useEffect, useState } from "react";
import { api } from "../api.js";

/**
 * Shows the IP the scanner is using — either "direct" (real WAN IP) or
 * "VPN" (SOCKS proxy exit IP, optionally through Tor). Polls /api/source-ip
 * every 30s so a proxy going up/down is reflected without a refresh.
 */
export default function SourceIpBadge() {
  const [info, setInfo] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const data = await api.getSourceIp();
        if (mounted) { setInfo(data); setErr(null); }
      } catch (e) {
        if (mounted) setErr(String(e.message || e));
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  if (err) {
    return (
      <div className="source-ip-badge source-ip-error" title={err}>
        <span className="source-ip-dot" />
        <span className="source-ip-label">IP: error</span>
      </div>
    );
  }
  if (!info) {
    return (
      <div className="source-ip-badge source-ip-loading">
        <span className="source-ip-dot" />
        <span className="source-ip-label">IP: …</span>
      </div>
    );
  }

  const isVpn = info.mode === "vpn" && info.chain_up;
  const isVpnDown = info.mode === "vpn" && !info.chain_up;
  const icon = isVpn ? (info.is_tor ? "🧅" : "🛡️") : (isVpnDown ? "⚠️" : "🌐");
  const modeLabel = isVpn
    ? (info.is_tor ? "VPN → Tor" : "VPN")
    : (isVpnDown ? "VPN DOWN" : "Direct");
  const tone = isVpn ? "ok" : (isVpnDown ? "danger" : "warn");

  return (
    <div className={`source-ip-badge source-ip-${tone}`}
         title={isVpnDown
           ? `VPN configured but chain is down: ${info.error || 'unknown'}`
           : `Scan traffic exits from ${info.ip || 'unknown'} (${modeLabel})`}>
      <span className="source-ip-icon">{icon}</span>
      <div className="source-ip-body">
        <div className="source-ip-mode">{modeLabel}</div>
        <div className="source-ip-ip">{info.ip || "unknown"}</div>
      </div>
    </div>
  );
}
