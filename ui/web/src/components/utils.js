export function methodColor(m) {
  const map = { GET: "#16a34a", POST: "#ca8a04", PUT: "#2563eb", DELETE: "#e7000b", PATCH: "#af50ff" };
  return map[(m || "").toUpperCase()] || "#828384";
}

// Parse a backend timestamp to epoch ms. The API emits ISO timestamps in UTC but
// WITHOUT a timezone suffix (e.g. "2026-09-18T15:24:31.5"); the JS Date parser
// treats such naive date-time strings as LOCAL, which made a just-started scan
// show an elapsed clock equal to the viewer's UTC offset (e.g. +5:30). Normalize:
// if there's no timezone marker, mark it UTC.
export function parseTs(ts) {
  if (ts == null) return NaN;
  if (typeof ts === "number") return ts;
  let s = String(ts).trim();
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s) && !/([zZ]|[+-]\d{2}:?\d{2})$/.test(s)) {
    s = s.replace(" ", "T") + "Z";
  }
  return new Date(s).getTime();
}

// Render any finding field safely as text. Probes/LLM sometimes emit a dict or
// list for details/proof/remediation/cwe_id etc.; passing an object as a React
// child throws "Objects are not valid as a React child" and blanks the screen.
export function asText(x) {
  if (x == null) return "";
  if (typeof x === "string") return x;
  if (typeof x === "number" || typeof x === "boolean") return String(x);
  try { return JSON.stringify(x, null, 2); } catch { return String(x); }
}

export function fmtDate(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(parseTs(ts));
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}
