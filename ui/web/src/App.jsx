import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import LiveScan from "./pages/LiveScan";
import Scans from "./pages/Scans";
import ScanDetail from "./pages/ScanDetail";
import AuditTrail from "./pages/AuditTrail";
import ReviewQueue from "./pages/ReviewQueue";
import Compare from "./pages/Compare";
import Settings from "./pages/Settings";
import Analytics from "./pages/Analytics";
import KnowledgeBase from "./pages/KnowledgeBase";
import SourceIpBadge from "./components/SourceIpBadge";
import { getApiKey } from "./api";

const DashIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
  </svg>
);
const TargetIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
  </svg>
);
const LiveIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M5 12h14" /><polyline points="12 5 19 12 12 19" />
  </svg>
);
const ScanIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
  </svg>
);
const CompareIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M16 3h5v5M8 3H3v5M3 16v5h5M21 16v5h-5" /><line x1="3" y1="12" x2="21" y2="12" />
  </svg>
);
const AuditIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const ReviewIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 11l3 3L22 4" />
    <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
  </svg>
);
const AnalyticsIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
  </svg>
);
const KnowledgeIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M2 3h6a4 4 0 014 4v14a3 3 0 00-3-3H2z" /><path d="M22 3h-6a4 4 0 00-4 4v14a3 3 0 013-3h7z" />
  </svg>
);
const SettingsIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
  </svg>
);

function AuthBanner() {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    function handler(e) {
      const d = e.detail || {};
      // If we have no key at all → guide the operator to Settings.
      // If we have a key but it was rejected → session invalid.
      setStatus(d.hasKey ? "invalid" : "missing");
    }
    window.addEventListener("ag:unauthorized", handler);
    return () => window.removeEventListener("ag:unauthorized", handler);
  }, []);

  if (!status) return null;
  const msg = status === "missing"
    ? "API key required. Open Settings and paste the key printed at the API's first boot."
    : "API key rejected by the server. It may have rotated. Open Settings to update.";

  return (
    <div style={{
      position: "fixed", top: 0, left: 240, right: 0,
      background: "#ff9800", color: "#000",
      padding: "10px 16px", zIndex: 1000,
      fontSize: 13, fontWeight: 500,
    }}>
      {msg}
      <button
        onClick={() => setStatus(null)}
        style={{ float: "right", background: "transparent", border: "1px solid #000",
                 color: "#000", padding: "2px 8px", cursor: "pointer", borderRadius: 3 }}
      >
        Dismiss
      </button>
    </div>
  );
}

export default function App() {
  // Log a one-liner at boot so the operator sees whether a key is loaded.
  useEffect(() => {
    const k = getApiKey();
    // eslint-disable-next-line no-console
    console.info("[AntiGravity] API client ready; key configured:", !!k);
  }, []);

  return (
    <BrowserRouter>
      <div className="app">
        <AuthBanner />
        <nav className="sidebar">
          <div className="logo">
            <div className="logo-icon">AG</div>
            <div className="logo-text">
              <span className="logo-name">AntiGravity</span>
              <span className="logo-version">v2.0 Autonomous</span>
            </div>
          </div>

          <div className="nav-section">
            <span className="nav-label">Operations</span>
            <NavLink to="/" end><DashIcon /> Dashboard</NavLink>
            <NavLink to="/targets"><TargetIcon /> Targets</NavLink>
            <NavLink to="/live"><LiveIcon /> Live Scans</NavLink>
            <NavLink to="/scans"><ScanIcon /> Scan History</NavLink>
          </div>

          <div className="nav-section">
            <span className="nav-label">Analysis</span>
            <NavLink to="/review"><ReviewIcon /> Review Queue</NavLink>
            <NavLink to="/compare"><CompareIcon /> Compare</NavLink>
            <NavLink to="/analytics"><AnalyticsIcon /> Analytics</NavLink>
            <NavLink to="/audit"><AuditIcon /> Audit Trail</NavLink>
          </div>

          <div className="nav-section">
            <span className="nav-label">Intelligence</span>
            <NavLink to="/knowledge"><KnowledgeIcon /> Knowledge Base</NavLink>
          </div>

          <div className="nav-section">
            <span className="nav-label">System</span>
            <NavLink to="/settings"><SettingsIcon /> Settings</NavLink>
          </div>

          <div className="sidebar-footer">
            <SourceIpBadge />
            <div className="sidebar-status">
              <span className="pulse" />
              <span>Engine Ready</span>
            </div>
          </div>
        </nav>
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/targets" element={<Targets />} />
            <Route path="/live" element={<LiveScan />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:scanId" element={<ScanDetail />} />
            <Route path="/review" element={<ReviewQueue />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/audit" element={<AuditTrail />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/knowledge" element={<KnowledgeBase />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
