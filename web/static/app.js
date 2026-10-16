// SENTINEL-FL shared front-end helpers (no external libraries: works offline on demo day)
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (v, d = 3) => (v === null || v === undefined || Number.isNaN(v)) ? "–" : (typeof v === "number" ? v.toFixed(d) : v);
const ago = ts => { if (!ts) return "–"; const s = Math.max(0, Date.now() / 1000 - ts); return s < 60 ? `${s.toFixed(0)} s ago` : s < 3600 ? `${(s / 60).toFixed(0)} min ago` : `${(s / 3600).toFixed(1)} h ago`; };
const clock = ts => ts ? new Date(ts * 1000).toLocaleTimeString() : "–";
const badge = (s, label) => `<span class="badge b-${esc(String(s).split(" ")[0])}">${esc(label ?? s)}</span>`;

const PAGES = {
  aggregator: [["/", "Control room"], ["/registry", "Registry & access"], ["/training", "Training rounds"], ["/attack", "Attack lab"],
               ["/ledger", "Audit ledger"], ["/alerts", "Alerts & e-mail"], ["/regulator", "Regulator · ARIA"], ["/results", "Results"]],
  bank: [["/", "Overview"], ["/transactions", "Transactions"], ["/alerts", "Alerts"], ["/training", "Local training"],
         ["/privacy", "Privacy budget"], ["/residency", "Data residency"]],
};

function shell(role, title, subtitle) {
  const here = location.pathname.replace(/\.html$/, "").replace(/\/index$/, "/") || "/";
  const tabs = PAGES[role].map(([h, t]) => `<a href="${h}" class="${h === here ? "on" : ""}">${t}</a>`).join("");
  document.body.insertAdjacentHTML("afterbegin", `<header class="top"><div class="brand">SENTINEL-FL<small>${esc(subtitle)}</small></div>
    <nav class="tabs">${tabs}</nav><span id="pill" class="status-pill">connecting…</span></header>
    <div class="modal" id="tokmodal"><div class="box"><h3 style="margin-top:0">Operator token</h3>
    <p class="muted">Actions on the aggregator are reserved for the consortium operator. The token is printed in the aggregator console
    (and saved in nodes/aggregator/admin_token.txt). With <span class="mono">cluster</span> it is <span class="mono">demo</span>.</p>
    <div class="row"><input id="tokin" placeholder="token" style="flex:1"><button class="solid" id="toksave">Save</button></div></div></div>
    <div class="toast" id="toast"></div>`);
  document.title = `${title} · SENTINEL-FL`;
  $("#toksave").onclick = () => { localStorage.setItem("sentinel_token", $("#tokin").value.trim()); $("#tokmodal").classList.remove("on"); };
}
function toast(msg, ms = 3500) { const t = $("#toast"); t.innerHTML = msg; t.style.display = "block"; clearTimeout(t._h); t._h = setTimeout(() => t.style.display = "none", ms); }
function pill(text, cls = "") { const p = $("#pill"); if (p) { p.textContent = text; p.className = "status-pill " + cls; } }

async function api(path) {
  const r = await fetch(path, { cache: "no-store" });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
async function post(path, body = {}) {
  const tok = localStorage.getItem("sentinel_token") || "";
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Admin-Token": tok }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (r.status === 403 && /token/.test(j.error || "")) { $("#tokmodal").classList.add("on"); throw new Error("operator token required"); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
function every(ms, fn) { const run = async () => { try { await fn(); } catch (e) { pill("node not reachable", "bad"); console.warn(e); } }; run(); return setInterval(run, ms); }

// ---------- SVG line chart -------------------------------------------------------------
function lineChart(el, series, o = {}) {
  const W = el.clientWidth || 600, H = o.height || 230, L = 42, R = 12, T = 14, B = 28;
  const xs = series.flatMap(s => s.points.map(p => p[0])), ys = series.flatMap(s => s.points.map(p => p[1])).filter(v => v !== null);
  const x0 = o.xmin ?? Math.min(...xs, 0), x1 = o.xmax ?? Math.max(...xs, 1);
  const y0 = o.ymin ?? Math.min(...ys, 0), y1 = o.ymax ?? Math.max(...ys, 1);
  const X = x => L + (x - x0) / ((x1 - x0) || 1) * (W - L - R), Y = y => T + (1 - (y - y0) / ((y1 - y0) || 1)) * (H - T - B);
  let g = "";
  for (let i = 0; i <= 4; i++) { const v = y0 + (y1 - y0) * i / 4; g += `<line x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}" stroke="#15213a"/><text x="${L - 6}" y="${Y(v) + 4}" fill="#7f93b2" font-size="10.5" text-anchor="end">${v.toFixed(o.yd ?? 2)}</text>`; }
  const step = Math.max(1, Math.ceil((x1 - x0) / 12));
  for (let x = Math.ceil(x0); x <= x1; x += step) g += `<text x="${X(x)}" y="${H - 9}" fill="#7f93b2" font-size="10.5" text-anchor="middle">${x}</text>`;
  if (o.xlabel) g += `<text x="${W - R}" y="${H - 1}" fill="#7f93b2" font-size="10" text-anchor="end">${esc(o.xlabel)}</text>`;
  (o.bands || []).forEach(b => g += `<rect x="${X(b.from)}" y="${T}" width="${Math.max(0, X(b.to) - X(b.from))}" height="${H - T - B}" fill="${b.color}" opacity=".13"/><text x="${X(b.from) + 4}" y="${T + 12}" fill="${b.color}" font-size="10.5">${esc(b.label || "")}</text>`);
  (o.refs || []).forEach(r => g += `<line x1="${L}" x2="${W - R}" y1="${Y(r.y)}" y2="${Y(r.y)}" stroke="${r.color || "#7f93b2"}" stroke-dasharray="5 5"/><text x="${W - R - 4}" y="${Y(r.y) - 5}" fill="${r.color || "#7f93b2"}" font-size="10.5" text-anchor="end">${esc(r.label)}</text>`);
  series.forEach(s => {
    const pts = s.points.filter(p => p[1] !== null);
    if (!pts.length) return;
    const d = pts.map((p, i) => `${i ? "L" : "M"}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join("");
    if (s.fill) g += `<path d="${d}L${X(pts.at(-1)[0])},${Y(y0)}L${X(pts[0][0])},${Y(y0)}Z" fill="${s.color}" opacity=".12"/>`;
    g += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="${s.width || 2}" ${s.dash ? `stroke-dasharray="${s.dash}"` : ""}/>`;
    if (s.dots !== false) pts.forEach(p => g += `<circle cx="${X(p[0])}" cy="${Y(p[1])}" r="2.6" fill="${s.color}"><title>${esc(s.name)} · ${p[0]}: ${p[1]}</title></circle>`);
  });
  const leg = series.filter(s => s.name).map((s, i) => `<g transform="translate(${L + 8 + i * 170},${T + 2})"><rect width="12" height="3" y="4" fill="${s.color}"/><text x="17" y="9" fill="#b9c8e3" font-size="11">${esc(s.name)}</text></g>`).join("");
  el.innerHTML = `<svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}">${g}${leg}</svg>`;
}

function barChart(el, items, o = {}) {   // items: [{label, value, color}]
  const W = el.clientWidth || 400, rowH = 22, H = items.length * rowH + 6, L = o.labelWidth || 120, max = Math.max(o.max || 0, ...items.map(i => i.value), 1);
  el.innerHTML = `<svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}">${items.map((it, i) => `
    <text x="${L - 8}" y="${i * rowH + 15}" fill="#b9c8e3" font-size="11.5" text-anchor="end">${esc(it.label)}</text>
    <rect x="${L}" y="${i * rowH + 5}" width="${W - L - 60}" height="12" rx="6" fill="#1c2a44"/>
    <rect x="${L}" y="${i * rowH + 5}" width="${(W - L - 60) * it.value / max}" height="12" rx="6" fill="${it.color || "#a78bfa"}"/>
    <text x="${W - 52}" y="${i * rowH + 15}" fill="#e6f1ff" font-size="11.5">${esc(it.text ?? it.value)}</text>`).join("")}</svg>`;
}

// ---------- consortium map (offline SVG, no tile server, no API key) ------------------------------
// Schematic: the aggregator in the centre; each bank placed in its real compass direction from Brussels,
// at a distance that grows with real distance, so labels never pile up on top of each other.
function euMap(el, agg, banks, o = {}) {
  const W = el.clientWidth || 700, H = o.height || 380, cx = W / 2, cy = H / 2, rmax = Math.min(W, H) / 2 - 46;
  let g = "";
  [0.35, 0.7, 1].forEach(f => g += `<circle cx="${cx}" cy="${cy}" r="${rmax * f}" fill="none" stroke="#13203a" stroke-dasharray="${f === 1 ? "0" : "3 6"}"/>`);
  for (let a = 0; a < 360; a += 30) { const r = a * Math.PI / 180; g += `<line x1="${cx}" y1="${cy}" x2="${cx + Math.cos(r) * rmax}" y2="${cy + Math.sin(r) * rmax}" stroke="#101b31"/>`; }
  [["N", 0, -1], ["E", 1, 0], ["S", 0, 1], ["W", -1, 0]].forEach(([t, dx, dy]) => g += `<text x="${cx + dx * (rmax + 16)}" y="${cy + dy * (rmax + 16) + 4}" fill="#2b4066" font-size="11" font-weight="700" text-anchor="middle">${t}</text>`);
  g += `<text x="14" y="20" fill="#2b4066" font-size="10.5" font-weight="700" letter-spacing="2">EU CONSORTIUM · BEARING AND DISTANCE FROM BRUSSELS</text>`;
  const pos = banks.filter(b => b.lat != null).map(b => {
    const dy = (b.lat - agg.lat) * 111, dx = (b.lon - agg.lon) * 111 * Math.cos(agg.lat * Math.PI / 180);
    const dist = Math.hypot(dx, dy), ang = Math.atan2(-dy, dx), r = Math.min(rmax, rmax * (0.45 + 0.55 * Math.min(1, dist / 1300)));
    return { b, x: cx + Math.cos(ang) * r, y: cy + Math.sin(ang) * r, dist };
  });
  pos.forEach(({ b, x, y, dist }) => {
    const c = b.status === "quarantined" || b.status === "revoked" ? "#ff4d6d" : b.status === "flagged" || b.status === "pending" ? "#ffb547" : "#2ee6a6";
    const live = b.online && !["quarantined", "revoked", "pending"].includes(b.status);
    const mx = (x + cx) / 2 + (cy - y) * .15, my = (y + cy) / 2 - (cx - x) * .15;
    g += `<path d="M${x},${y} Q${mx},${my} ${cx},${cy}" fill="none" stroke="${c}" stroke-width="2.2" opacity="${live ? .9 : .3}" class="${live ? "arc" : ""}" ${live ? "" : 'stroke-dasharray="2 8"'}/>`;
    g += `<circle cx="${x}" cy="${y}" r="18" fill="${c}" opacity=".13" class="${b.status === "quarantined" ? "pulse" : ""}"/><circle cx="${x}" cy="${y}" r="9" fill="${c}"/>`;
    const right = x >= cx - 5, tx = right ? x + 16 : x - 16, anc = right ? "start" : "end";
    g += `<text x="${tx}" y="${y - 4}" fill="#e6f1ff" font-size="13" font-weight="700" text-anchor="${anc}">${esc(b.name || "Bank " + b.id)}</text>`;
    g += `<text x="${tx}" y="${y + 11}" fill="#7f93b2" font-size="11" text-anchor="${anc}">${esc(b.city || "")}, ${esc(b.country || "")} · ${dist.toFixed(0)} km</text>`;
    g += `<text x="${tx}" y="${y + 25}" fill="${c}" font-size="11" font-weight="700" text-anchor="${anc}">${esc(b.status)}${b.online ? "" : " · offline"}${b.red_team ? " · red team" : ""}</text>`;
  });
  g += `<circle cx="${cx}" cy="${cy}" r="24" fill="#3ee6ff" opacity=".14" class="pulse"/><circle cx="${cx}" cy="${cy}" r="11" fill="#3ee6ff"/>`;
  g += `<text x="${cx}" y="${cy + 40}" fill="#3ee6ff" font-size="12" font-weight="700" text-anchor="middle">Aggregator · ${esc(agg.city || "Brussels")}</text>`;
  el.innerHTML = `<svg width="100%" height="${H}" viewBox="0 0 ${W} ${H}" style="background:#060a13;border-radius:8px">${g}</svg>`;
}
