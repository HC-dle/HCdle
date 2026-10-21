// HCdle backend: login con PIN, rachas y ScoreBoard.
// Una sola función, rutas bajo /api/*
import crypto from "node:crypto";

export const config = { path: "/api/*" };

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

const norm = (s) =>
  String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/\s+/g, "");
const NICK_BY_KEY = new Map(NICKS.map((n) => [norm(n), n]));

// ---------- Utilidades ----------
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

function hashPin(pin, salt = crypto.randomBytes(16).toString("hex")) {
  const h = crypto.scryptSync(pin, salt, 32).toString("hex");
  return { salt, hash: h };
}
function checkPin(pin, u) {
  const h = crypto.scryptSync(pin, u.salt, 32);
  const a = Buffer.from(u.hash, "hex");
  return a.length === h.length && crypto.timingSafeEqual(a, h);
}
function safeEq(a, b) {
  const x = crypto.createHash("sha256").update(String(a)).digest();
  const y = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

async function getSecret(store) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  let s = await store.get("meta:secret");
  if (!s) {
    s = crypto.randomBytes(32).toString("hex");
    await store.set("meta:secret", s);
  }
  return s;
}
function sign(secret, payload) {
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}
async function makeToken(store, key) {
  const secret = await getSecret(store);
  const payload = Buffer.from(JSON.stringify({ k: key, e: Date.now() + TOKEN_MS })).toString("base64url");
  return payload + "." + sign(secret, payload);
}
async function readToken(store, req) {
  const h = req.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [payload, sig] = t.split(".");
  if (!payload || !sig) return null;
  const secret = await getSecret(store);
  if (!safeEq(sig, sign(secret, payload))) return null;
  try {
    const p = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (!p.k || p.e < Date.now() || !NICK_BY_KEY.has(p.k)) return null;
    return p.k;
  } catch { return null; }
}

const loadUser = async (store, key) => (await store.get("user:" + key, { type: "json" })) || null;
const saveUser = (store, key, u) => store.setJSON("user:" + key, u);

// Racha vigente: si no completó ayer ni hoy, la racha efectiva es 0.
function view(u, today) {
  const streak = u && u.lastDay && u.lastDay >= addDays(today, -1) ? u.streak || 0 : 0;
  return { streak, best: Math.max(u?.best || 0, streak), doneToday: !!(u && u.lastDay === today) };
}

// ---------- Handler ----------
export async function handle(req, store, now = Date.now()) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const today = todayAR(now);
  let body = {};
  if (req.method === "POST") {
    try { body = await req.json(); } catch { return err(400, "JSON inválido"); }
  }

  if (path === "nicks" && req.method === "GET") {
    const out = [];
    for (const n of NICKS) {
      const u = await loadUser(store, norm(n));
      out.push({ nick: n, registered: !!(u && u.hash) });
    }
    return json({ nicks: out });
  }

  if (path === "scoreboard" && req.method === "GET") {
    const rows = [];
    for (const n of NICKS) {
      const u = await loadUser(store, norm(n));
      rows.push({ nick: n, ...view(u, today) });
    }
    rows.sort((a, b) => b.streak - a.streak || b.best - a.best || a.nick.localeCompare(b.nick));
    return json({ today, rows });
  }

  if (path === "login" && req.method === "POST") {
    const key = norm(body.nick);
    const nick = NICK_BY_KEY.get(key);
    const pin = String(body.pin || "");
    if (!nick) return err(400, "Nick no permitido");
    if (!/^\d{4,8}$/.test(pin)) return err(400, "El PIN debe tener entre 4 y 8 números");
    let u = (await loadUser(store, key)) || { streak: 0, best: 0, lastDay: null };
    if (u.lockUntil && u.lockUntil > now)
      return err(429, "Demasiados intentos. Probá en unos minutos.", { retryInMs: u.lockUntil - now });
    let created = false;
    if (!u.hash) {
      Object.assign(u, hashPin(pin));
      u.fails = 0; u.lockUntil = 0;
      created = true;
    } else if (!checkPin(pin, u)) {
      u.fails = (u.fails || 0) + 1;
      if (u.fails >= MAX_FAILS) { u.lockUntil = now + LOCK_MS; u.fails = 0; }
      await saveUser(store, key, u);
      return err(401, "PIN incorrecto");
    } else { u.fails = 0; u.lockUntil = 0; }
    await saveUser(store, key, u);
    return json({ token: await makeToken(store, key), nick, created, ...view(u, today), today });
  }

  if (path === "me" && req.method === "GET") {
    const key = await readToken(store, req);
    if (!key) return err(401, "Sesión inválida");
    const u = await loadUser(store, key);
    if (!u || !u.hash) return err(401, "Sesión inválida");
    return json({ nick: NICK_BY_KEY.get(key), ...view(u, today), today });
  }

  if (path === "complete" && req.method === "POST") {
    const key = await readToken(store, req);
    if (!key) return err(401, "Sesión inválida");
    const u = await loadUser(store, key);
    if (!u || !u.hash) return err(401, "Sesión inválida");
    if (u.lastDay !== today) {
      u.streak = u.lastDay === addDays(today, -1) ? (u.streak || 0) + 1 : 1;
      u.best = Math.max(u.best || 0, u.streak);
      u.lastDay = today;
      await saveUser(store, key, u);
    }
    return json({ nick: NICK_BY_KEY.get(key), ...view(u, today), today });
  }

  if (path === "admin/reset" && req.method === "POST") {
    const adminKey = process.env.ADMIN_KEY;
    if (!adminKey) return err(500, "ADMIN_KEY no configurada");
    if (!safeEq(body.key || "", adminKey)) return err(403, "Clave de admin incorrecta");
    const key = norm(body.nick);
    if (!NICK_BY_KEY.has(key)) return err(400, "Nick no permitido");
    const u = (await loadUser(store, key)) || { streak: 0, best: 0, lastDay: null };
    delete u.hash; delete u.salt; u.fails = 0; u.lockUntil = 0;
    await saveUser(store, key, u);
    return json({ ok: true, nick: NICK_BY_KEY.get(key) });
  }

  return err(404, "Ruta no encontrada");
}

export default async (req) => {
  const { getStore } = await import("@netlify/blobs");
  return handle(req, getStore("hcdle"));
};
