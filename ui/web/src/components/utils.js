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

// Clean the stacked METHOD:/scheme:// artifact ("GET:get://get://https://host/x")
// that older scans baked into finding titles/locations, for display only. Returns
// a readable "GET https://host/x". Leaves already-clean strings untouched.
export function cleanUrl(s) {
  if (!s) return s;
  let t = String(s).trim();
  // Pull a leading HTTP method off, remember it.
  let method = "";
  const mm = t.match(/^\/?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[:\s]/i);
  if (mm) { method = mm[1].toUpperCase(); t = t.slice(mm[0].length); }
  // If a real http(s):// appears (possibly after get://get:// junk), keep from the
  // LAST one; else strip leading pseudo-scheme "word://" prefixes.
  const ms = [...t.matchAll(/https?:\/\//gi)];
  if (ms.length) t = t.slice(ms[ms.length - 1].index);
  else t = t.replace(/^(?:[a-z][a-z0-9+.\-]*:\/\/)+/i, "").replace(/^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS):/i, "");
  t = t.trim();
  return method && t ? `${method} ${t}` : t || String(s);
}

// Clean a finding title: strip the URL artifact inside it while keeping the label.
export function cleanTitle(s) {
  if (!s) return s;
  // Titles look like "Missing Authentication: GET GET:get://get://https://host/x".
  return String(s).replace(/((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)[:\s])+(?:[a-z]+:\/\/)*(https?:\/\/\S+)/gi,
    (_m, _p1, url) => cleanUrl(url));
}

// Build human "how to reproduce" steps + a curl PoC when the finding stored none,
// derived from its method/location/type. Keeps the panel actionable for every
// finding instead of "No reproduction steps available."
export function reproSteps(v) {
  const loc = cleanUrl(v.location || v.target || v.url || "");
  const parts = loc.split(" ");
  const method = (v.method || (parts.length > 1 ? parts[0] : "GET")).toUpperCase();
  const url = parts.length > 1 ? parts.slice(1).join(" ") : loc;
  if (!url) return "";
  const type = (v.type || v.vuln_type || "").toString();
  const lines = [
    `1. Send: ${method} ${url}`,
    `2. Observe the response (status, headers, body).`,
  ];
  if (/auth|idor|bola|access|privilege|forced/i.test(type))
    lines.push(`3. Repeat without credentials (or as a different/low-priv user) — a ${method} that still returns 200 with the protected data confirms the access-control gap.`);
  else if (/inject|sqli|xss|ssti|traversal/i.test(type))
    lines.push(`3. Compare the response to a benign baseline — reflected payload / error signature / differential behaviour confirms it.`);
  else
    lines.push(`3. Compare against expected secure behaviour; a deviation confirms the finding.`);
  const curl = `curl -i -X ${method} "${url}"`;
  return { text: lines.join("\n"), curl };
}

export function fmtDate(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(parseTs(ts));
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}
