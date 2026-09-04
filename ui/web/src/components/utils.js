export function methodColor(m) {
  const map = { GET: "#16a34a", POST: "#ca8a04", PUT: "#2563eb", DELETE: "#e7000b", PATCH: "#af50ff" };
  return map[(m || "").toUpperCase()] || "#828384";
}

export function fmtDate(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}
