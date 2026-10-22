// HCdle backend (Cloudflare Worker): login con PIN, rachas y ScoreBoard.
// Rutas bajo /api/*. El resto lo sirve la carpeta public/ como assets.
// Almacenamiento: KV (binding HCDLE_KV). Secrets opcionales/requeridos: SESSION_SECRET, ADMIN_KEY.

// ---------- Configuración ----------
const NICKS = [
  "Pnkie", "Cankkun", "Naza", "Andy", "Wal", "Gonza", "Ramitads", "Sanpo",
  "Silvagina", "Fabri", "El Topo", "Marcodz", "Corren", "Brunito", "Pitusas",
  "Scribble", "Polkaz", "El Patrón",
];
const TZ = "America/Argentina/Buenos_Aires";
const MAX_FAILS = 5;
const LOCK_MS = 10 * 60 * 1000;
const TOKEN_MS = 90 * 24 * 3600 * 1000;
const PBKDF2_ITER = 100000; // máximo permitido en Workers

const norm = (s) =>
  String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, "");
const NICK_BY_KEY = new Map(NICKS.map((n) => [norm(n), n]));

// ---------- Utilidades ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

export function todayAR(now = Date.now()) {
  return new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(now));
}
export function addDays(dateStr, n) {
  const d = new Date(dateStr + "T12:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const err = (status, msg, extra = {}) => json({ error: msg, ...extra }, status);

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
};

async function derive(pin, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: PBKDF2_ITER },
    key,
    256
  );
  return toHex(bits);
}
async function hashPin(pin) {
  const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, hash: await derive(pin, salt) };
}
async function safeEq(a, b) {
  const [x, y] = await Promise.all(
    [a, b].map(async (s) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(String(s)))))
  );
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}
async function checkPin(pin, u) {
  return safeEq(await derive(pin, u.salt), u.hash);
}

async function getSecret(env) {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  let s = await env.HCDLE_KV.get("meta:secret");
  if (!s) {
    s = toHex(crypto.getRandomValues(new Uint8Array(32)));
    await env.HCDLE_KV.put("meta:secret", s);
  }
  return s;
}
async function sign(secret, payload) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(payload)));
}
async function makeToken(env, key) {
  const secret = await getSecret(env);
  const payload = b64u(enc.encode(JSON.stringify({ k: key, e: Date.now() + TOKEN_MS })));
  return payload + "." + (await sign(secret, payload));
}
async function readToken(env, req) {
  const h = req.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [payload, sig] = t.split(".");
  if (!payload || !sig) return null;
  const secret = await getSecret(env);
  if (!(await safeEq(sig, await sign(secret, payload)))) return null;
  try {
    const p = JSON.parse(dec.decode(unb64u(payload)));
    if (!p.k || p.e < Date.now() || !NICK_BY_KEY.has(p.k)) return null;
    return p.k;
  } catch { return null; }
}

const loadUser = async (env, key) => (await env.HCDLE_KV.get("user:" + key, "json")) || null;
const saveUser = (env, key, u) => env.HCDLE_KV.put("user:" + key, JSON.stringify(u));

// Racha vigente: si no completó ayer ni hoy, la racha efectiva es 0.
function view(u, today) {
  const streak = u && u.lastDay && u.lastDay >= addDays(today, -1) ? u.streak || 0 : 0;
  return { streak, best: Math.max(u?.best || 0, streak), doneToday: !!(u && u.lastDay === today) };
}

// ---------- Handler ----------
export async function handle(req, env, now = Date.now()) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const today = todayAR(now);
  let body = {};
  if (req.method === "POST") {
    try { body = await req.json(); } catch { return err(400, "JSON inválido"); }
  }

  if (path === "nicks" && req.method === "GET") {
    const users = await Promise.all(NICKS.map((n) => loadUser(env, norm(n))));
    return json({ nicks: NICKS.map((n, i) => ({ nick: n, registered: !!(users[i] && users[i].hash) })) });
  }

  if (path === "scoreboard" && req.method === "GET") {
    const users = await Promise.all(NICKS.map((n) => loadUser(env, norm(n))));
    const rows = NICKS.map((n, i) => ({ nick: n, ...view(users[i], today) }));
    rows.sort((a, b) => b.streak - a.streak || b.best - a.best || a.nick.localeCompare(b.nick));
    return json({ today, rows });
  }

  if (path === "login" && req.method === "POST") {
    const key = norm(body.nick);
    const nick = NICK_BY_KEY.get(key);
    const pin = String(body.pin || "");
    if (!nick) return err(400, "Nick no permitido");
    if (!/^\d{4,8}$/.test(pin)) return err(400, "El PIN debe tener entre 4 y 8 números");
    let u = (await loadUser(env, key)) || { streak: 0, best: 0, lastDay: null };
    if (u.lockUntil && u.lockUntil > now)
      return err(429, "Demasiados intentos. Probá en unos minutos.", { retryInMs: u.lockUntil - now });
    let created = false;
    if (!u.hash) {
      Object.assign(u, await hashPin(pin));
      u.fails = 0; u.lockUntil = 0;
      created = true;
    } else if (!(await checkPin(pin, u))) {
      u.fails = (u.fails || 0) + 1;
      if (u.fails >= MAX_FAILS) { u.lockUntil = now + LOCK_MS; u.fails = 0; }
      await saveUser(env, key, u);
      return err(401, "PIN incorrecto");
    } else { u.fails = 0; u.lockUntil = 0; }
    await saveUser(env, key, u);
    return json({ token: await makeToken(env, key), nick, created, ...view(u, today), today });
  }

  if (path === "me" && req.method === "GET") {
    const key = await readToken(env, req);
    if (!key) return err(401, "Sesión inválida");
    const u = await loadUser(env, key);
    if (!u || !u.hash) return err(401, "Sesión inválida");
    return json({ nick: NICK_BY_KEY.get(key), ...view(u, today), today });
  }

  if (path === "complete" && req.method === "POST") {
    const key = await readToken(env, req);
    if (!key) return err(401, "Sesión inválida");
    const u = await loadUser(env, key);
    if (!u || !u.hash) return err(401, "Sesión inválida");
    if (u.lastDay !== today) {
      u.streak = u.lastDay === addDays(today, -1) ? (u.streak || 0) + 1 : 1;
      u.best = Math.max(u.best || 0, u.streak);
      u.lastDay = today;
      await saveUser(env, key, u);
    }
    return json({ nick: NICK_BY_KEY.get(key), ...view(u, today), today });
  }

  if (path === "admin/reset" && req.method === "POST") {
    const adminKey = env.ADMIN_KEY;
    if (!adminKey) return err(500, "ADMIN_KEY no configurada");
    if (!(await safeEq(body.key || "", adminKey))) return err(403, "Clave de admin incorrecta");
    const key = norm(body.nick);
    if (!NICK_BY_KEY.has(key)) return err(400, "Nick no permitido");
    const u = (await loadUser(env, key)) || { streak: 0, best: 0, lastDay: null };
    delete u.hash; delete u.salt; u.fails = 0; u.lockUntil = 0;
    await saveUser(env, key, u);
    return json({ ok: true, nick: NICK_BY_KEY.get(key) });
  }

  // Suma `delta` (default 1) a la racha de varios nicks. Solo admin.
  // Body: { key, nicks: ["Andy", ...], delta?: 1 }
  if (path === "admin/streak" && req.method === "POST") {
    const adminKey = env.ADMIN_KEY;
    if (!adminKey) return err(500, "ADMIN_KEY no configurada");
    if (!(await safeEq(body.key || "", adminKey))) return err(403, "Clave de admin incorrecta");
    const delta = body.delta === undefined ? 1 : body.delta;
    if (!Number.isInteger(delta) || delta < 1 || delta > 30) return err(400, "delta inválido (1 a 30)");
    const list = Array.isArray(body.nicks) ? body.nicks : [];
    if (!list.length) return err(400, "Faltan nicks");
    const keys = list.map(norm);
    const bad = list.filter((_, i) => !NICK_BY_KEY.has(keys[i]));
    if (bad.length) return err(400, "Nick no permitido", { nicks: bad });
    const yesterday = addDays(today, -1);
    const rows = [];
    for (const key of [...new Set(keys)]) {
      const u = (await loadUser(env, key)) || { streak: 0, best: 0, lastDay: null };
      const cur = view(u, today).streak;
      if (cur === 0) u.lastDay = yesterday; // para que la racha sumada quede vigente
      u.streak = cur + delta;
      u.best = Math.max(u.best || 0, u.streak);
      await saveUser(env, key, u);
      rows.push({ nick: NICK_BY_KEY.get(key), ...view(u, today) });
    }
    return json({ ok: true, today, rows });
  }

  return err(404, "Ruta no encontrada");
}

export default {
  async fetch(req, env) {
    const { pathname } = new URL(req.url);
    if (pathname === "/api" || pathname.startsWith("/api/")) return handle(req, env);
    return env.ASSETS.fetch(req);
  },
};
