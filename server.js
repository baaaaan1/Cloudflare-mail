/**
 * Cloudflare Email Routing Panel — API server (Express + Axios)
 * Simplified: Password-only auth, proper pagination, private mode.
 */

const express = require('express');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.disable('x-powered-by');
// Caddy terminates TLS and forwards the original client address/protocol.
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));
app.use((req, res, next) => {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "frame-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use((req, _res, next) => {
  try { console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`); } catch {} finally { next(); }
});

const PORT = process.env.PORT || 3000;

if (!process.env.CLOUDFLARE_API_TOKEN || !process.env.CLOUDFLARE_ACCOUNT_ID || !process.env.CLOUDFLARE_ZONE_ID) {
  console.warn('[WARN] Missing .env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ZONE_ID. Configure via Settings.');
}
if (!process.env.CLOUDFLARE_D1_DATABASE_ID) {
  console.warn('[WARN] Missing .env: CLOUDFLARE_D1_DATABASE_ID. Inbox features will be disabled.');
}

// ── Cloudflare API Client ──────────────────────────────────────────────
const cf = axios.create({
  baseURL: 'https://api.cloudflare.com/client/v4',
  headers: { Authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN || ''}` },
  timeout: 30000,
});

function updateCfToken() {
  cf.defaults.headers['Authorization'] = `Bearer ${process.env.CLOUDFLARE_API_TOKEN || ''}`;
}

// ── Auth (Password only) ───────────────────────────────────────────────
const PASSWORD_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 jam
const passwordSessions = new Map();

function getPasswordHash() {
  const v = process.env.PASSWORD_HASH;
  return v && v.trim() ? v.trim() : null;
}
function getPasswordSalt() {
  const v = process.env.PASSWORD_SALT;
  return v && v.trim() ? v.trim() : null;
}
function isPasswordConfigured() {
  return !!(getPasswordHash() && getPasswordSalt());
}

function decodePasswordHash(value) {
  if (!value) return null;
  const trimmed = String(value).trim();
  if (!trimmed) return null;
  if (/^[0-9a-f]+$/i.test(trimmed) && trimmed.length % 2 === 0) {
    return Buffer.from(trimmed, 'hex');
  }
  try { return Buffer.from(trimmed, 'base64'); } catch { return null; }
}

function verifyPasswordInput(password) {
  const hashValue = getPasswordHash();
  const saltValue = getPasswordSalt();
  if (!hashValue || !saltValue) return false;
  const storedHash = decodePasswordHash(hashValue);
  if (!storedHash || !storedHash.length) return false;
  try {
    const derived = crypto.scryptSync(String(password || ''), String(saltValue), storedHash.length);
    return crypto.timingSafeEqual(derived, storedHash);
  } catch { return false; }
}

// ── Cache ──────────────────────────────────────────────────────────────
const DOMAIN_CACHE_TTL_MS = 5 * 60 * 1000;
const domainCache = { data: null, expiresAt: 0 };
const WORKER_CACHE_TTL_MS = 5 * 60 * 1000;
const workerCache = { data: null, expiresAt: 0 };

function resetDomainCache() { domainCache.data = null; domainCache.expiresAt = 0; }
function resetWorkerCache() { workerCache.data = null; workerCache.expiresAt = 0; }

// ── Cookie helpers ─────────────────────────────────────────────────────
const COOKIE_PASSWORD_SESSION_ID = 'pwd_session_id';

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach((part) => {
    const [rawKey, ...rest] = part.trim().split('=');
    if (!rawKey) return;
    cookies[rawKey] = decodeURIComponent(rest.join('='));
  });
  return cookies;
}

function serializeCookie(name, value, options = {}) {
  const segments = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) segments.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge / 1000))}`);
  if (options.path) segments.push(`Path=${options.path}`);
  if (options.httpOnly) segments.push('HttpOnly');
  if (options.sameSite) segments.push(`SameSite=${options.sameSite}`);
  if (options.secure) segments.push('Secure');
  return segments.join('; ');
}

function appendSetCookie(res, cookie) {
  const existing = res.getHeader('Set-Cookie');
  const next = Array.isArray(existing) ? existing.slice() : (existing ? [existing] : []);
  next.push(cookie);
  res.setHeader('Set-Cookie', next);
}

function getCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'Strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  };
}

function setPasswordSessionCookie(res, sessionId, expiresAt) {
  if (!sessionId) return;
  const maxAge = expiresAt ? Math.max(0, expiresAt - Date.now()) : PASSWORD_SESSION_TTL_MS;
  appendSetCookie(res, serializeCookie(COOKIE_PASSWORD_SESSION_ID, sessionId, { ...getCookieOptions(), maxAge }));
}

function clearAuthCookies(res) {
  const opts = { ...getCookieOptions(), maxAge: 0 };
  appendSetCookie(res, serializeCookie(COOKIE_PASSWORD_SESSION_ID, '', opts));
}

// ── Rate Limiter ───────────────────────────────────────────────────────
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const RATE_LIMIT_MAX = 10;
const rateLimitStore = new Map();

function rateLimit(keyPrefix, max = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW_MS) {
  return (req, res, next) => {
    const key = `${keyPrefix}:${req.ip}`;
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, start: now };
    if (now - entry.start > windowMs) { entry.count = 0; entry.start = now; }
    entry.count += 1;
    rateLimitStore.set(key, entry);
    if (entry.count > max) return res.status(429).json({ error: 'Too many requests. Try again later.' });
    return next();
  };
}

// ── Auth middleware ────────────────────────────────────────────────────
const authMiddleware = (req, res, next) => {
  if (!isPasswordConfigured()) {
    return next(); // no password configured? allow access (for setup)
  }
  const cookies = parseCookies(req.headers.cookie || '');
  const passwordSessionId = cookies[COOKIE_PASSWORD_SESSION_ID];

  if (passwordSessionId && passwordSessions.has(passwordSessionId)) {
    const expiresAt = passwordSessions.get(passwordSessionId);
    if (!expiresAt || Date.now() <= expiresAt) {
      return next();
    } else {
      passwordSessions.delete(passwordSessionId);
      clearAuthCookies(res);
    }
  }
  return res.status(401).json({ error: 'Unauthorized. Please login.' });
};

// ── Config helpers ────────────────────────────────────────────────────
function getEnvVariable(key) {
  try {
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8');
      const match = content.match(new RegExp(`^${key}=(.*)$`, 'm'));
      return match ? match[1].trim() : null;
    }
  } catch (e) { /* ignore */ }
  return process.env[key];
}

function sanitizeEnvValue(label, value) {
  if (value === undefined) return { value: undefined };
  const text = String(value);
  if (/[\r\n\0]/.test(text)) return { error: `${label} contains invalid characters` };
  if (text.length > 512) return { error: `${label} is too long` };
  return { value: text.trim() };
}

// ── Login endpoint ─────────────────────────────────────────────────────
app.post('/api/login', rateLimit('login'), (req, res) => {
  if (!isPasswordConfigured()) {
    return res.status(400).json({ error: 'Password not configured. Set PASSWORD_HASH and PASSWORD_SALT in .env' });
  }
  const password = String(req.body?.password || '').trim();
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (!verifyPasswordInput(password)) return res.status(401).json({ error: 'Invalid password' });

  const sessionId = crypto.randomBytes(16).toString('hex');
  const expiresAt = Date.now() + PASSWORD_SESSION_TTL_MS;
  passwordSessions.set(sessionId, expiresAt);
  clearAuthCookies(res);
  setPasswordSessionCookie(res, sessionId, expiresAt);
  res.json({ ok: true, sessionId });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie || '');
  const sid = cookies[COOKIE_PASSWORD_SESSION_ID];
  if (sid) passwordSessions.delete(sid);
  clearAuthCookies(res);
  res.json({ ok: true });
});

app.get('/api/auth-status', (req, res) => {
  const cookies = parseCookies(req.headers.cookie || '');
  const sid = cookies[COOKIE_PASSWORD_SESSION_ID];
  let loggedIn = false;
  if (sid && passwordSessions.has(sid)) {
    const exp = passwordSessions.get(sid);
    if (exp && Date.now() <= exp) loggedIn = true;
  }
  res.json({
    passwordEnabled: isPasswordConfigured(),
    loggedIn,
    authRequired: true,
  });
});

app.get('/api/session', (_req, res) => {
  res.json({ ok: true });
});

// ── Apply auth to all /api routes (except login, logout, auth-status) ──
app.use('/api', (req, res, next) => {
  // Skip auth for login/logout/auth-status/session
  if (req.path === '/login' || req.path === '/logout' || req.path === '/auth-status' || req.path === '/session') {
    return next();
  }
  return authMiddleware(req, res, next);
});

// ── CF API Helpers with proper pagination ──────────────────────────────

async function paginateAll(url, params = {}) {
  const allResults = [];
  let page = 1;
  let totalPages = 1;
  const baseParams = { ...params, per_page: params.per_page || 100 };
  do {
    baseParams.page = page;
    const res = await cf.get(url, { params: baseParams });
    const data = res.data || {};
    const results = data.result || [];
    allResults.push(...results);
    totalPages = (data.result_info && data.result_info.total_pages) || 1;
    page += 1;
  } while (page <= totalPages);
  return allResults;
}

async function listDestinations() {
  return await paginateAll(`/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses`);
}

async function createDestination(email) {
  const res = await cf.post(`/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses`, { email });
  return res.data.result;
}

async function deleteDestination(id) {
  const res = await cf.delete(`/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses/${id}`);
  return res.data.result;
}

async function listRules(zoneId = process.env.CLOUDFLARE_ZONE_ID) {
  if (!zoneId) throw new Error('CLOUDFLARE_ZONE_ID not configured');
  return await paginateAll(`/zones/${zoneId}/email/routing/rules`);
}

async function getRule(ruleId, zoneId = process.env.CLOUDFLARE_ZONE_ID) {
  if (!zoneId) throw new Error('CLOUDFLARE_ZONE_ID not configured');
  const res = await cf.get(`/zones/${zoneId}/email/routing/rules/${ruleId}`);
  return res.data.result;
}

async function createRule(customEmail, destinationInput, type = 'forward', zoneIdOverride = null) {
  const zoneId = zoneIdOverride || process.env.CLOUDFLARE_ZONE_ID;
  if (!zoneId) throw new Error('CLOUDFLARE_ZONE_ID not configured');
  let actions;
  if (type === 'worker') {
    actions = [{ type: 'worker', value: [destinationInput] }];
  } else if (type === 'drop') {
    actions = [{ type: 'drop' }];
  } else {
    const value = await resolveDestinationArray(destinationInput);
    actions = [{ type: 'forward', value }];
  }
  const body = {
    name: `route:${customEmail}`,
    enabled: true,
    matchers: [{ type: 'literal', field: 'to', value: customEmail }],
    actions
  };
  const res = await cf.post(`/zones/${zoneId}/email/routing/rules`, body);
  return res.data.result;
}

async function updateRule(ruleId, { customEmail, destinationId, enabled, type, zoneId }) {
  const targetZoneId = zoneId || process.env.CLOUDFLARE_ZONE_ID;
  if (!targetZoneId) throw new Error('CLOUDFLARE_ZONE_ID not configured');
  const current = await getRule(ruleId, targetZoneId);
  let actions = current.actions;

  const targetType = type || (actions[0] && actions[0].type) || 'forward';
  if (type || destinationId) {
    if (targetType === 'drop') {
      actions = [{ type: 'drop' }];
    } else if (targetType === 'worker') {
      const val = destinationId || (actions[0] && actions[0].value && actions[0].value[0]);
      if (val) actions = [{ type: 'worker', value: [val] }];
    } else {
      const val = destinationId || (actions[0] && actions[0].value && actions[0].value[0]);
      if (val && destinationId) {
        const value = await resolveDestinationArray(destinationId);
        actions = [{ type: 'forward', value }];
      }
    }
  }
  const body = {
    name: current.name || (customEmail ? `route:${customEmail}` : undefined),
    enabled: typeof enabled === 'boolean' ? enabled : !!current.enabled,
    matchers: customEmail ? [{ type: 'literal', field: 'to', value: customEmail }] : current.matchers,
    actions
  };
  const res = await cf.put(`/zones/${targetZoneId}/email/routing/rules/${ruleId}`, body);
  return res.data.result;
}

async function deleteRule(ruleId, zoneIdOverride = null) {
  const zoneId = zoneIdOverride || process.env.CLOUDFLARE_ZONE_ID;
  if (!zoneId) throw new Error('CLOUDFLARE_ZONE_ID not configured');
  const res = await cf.delete(`/zones/${zoneId}/email/routing/rules/${ruleId}`);
  return res.data.result;
}

async function resolveDestinationArray(input) {
  if (!input) throw new Error('destination required');
  if (/@/.test(input)) return [String(input).trim().toLowerCase()];
  const r = await cf.get(`/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/email/routing/addresses/${input}`);
  if (!r.data || !r.data.result || !r.data.result.email) throw new Error('destination not found: ' + input);
  if (r.data.result.verified === false) throw new Error('destination not verified: ' + r.data.result.email);
  return [String(r.data.result.email).trim().toLowerCase()];
}

async function listDomains() {
  if (domainCache.data && domainCache.expiresAt > Date.now()) return domainCache.data;
  if (!process.env.CLOUDFLARE_API_TOKEN) throw new Error('CLOUDFLARE_API_TOKEN not configured');
  const params = { per_page: 50 };
  if (process.env.CLOUDFLARE_ACCOUNT_ID) params['account.id'] = process.env.CLOUDFLARE_ACCOUNT_ID;
  const zones = await paginateAll('/zones', params);
  const results = zones.filter(z => z && z.id && z.name).map(z => ({ id: z.id, name: z.name }));
  domainCache.data = results;
  domainCache.expiresAt = Date.now() + DOMAIN_CACHE_TTL_MS;
  return results;
}

async function listWorkers() {
  if (workerCache.data && workerCache.expiresAt > Date.now()) return workerCache.data;
  if (!process.env.CLOUDFLARE_API_TOKEN) throw new Error('CLOUDFLARE_API_TOKEN not configured');
  if (!process.env.CLOUDFLARE_ACCOUNT_ID) throw new Error('CLOUDFLARE_ACCOUNT_ID not configured');
  const res = await cf.get(`/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/workers/scripts`, { params: { per_page: 100 } });
  const scripts = res.data && res.data.result ? res.data.result : [];
  const workers = scripts
    .map((script) => { const name = script.id || script.name || script.script || ''; return name ? { id: name, name } : null; })
    .filter(Boolean);
  workerCache.data = workers;
  workerCache.expiresAt = Date.now() + WORKER_CACHE_TTL_MS;
  return workers;
}

async function queryD1(sql, params = []) {
  if (!process.env.CLOUDFLARE_D1_DATABASE_ID) throw new Error('D1 Database ID not configured');
  if (process.env.CLOUDFLARE_D1_DATABASE_ID.includes('REPLACE')) throw new Error('D1 Database ID is invalid (placeholder detected)');
  const res = await cf.post(`/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${process.env.CLOUDFLARE_D1_DATABASE_ID}/query`, { sql, params });
  return (res.data.result && res.data.result[0] && res.data.result[0].results) || [];
}

function eToMessage(e) {
  if (e && e.response && e.response.data) {
    try {
      const d = e.response.data;
      if (d.errors && d.errors.length) return JSON.stringify(d.errors, null, 2);
      return JSON.stringify(d, null, 2);
    } catch {}
  }
  return String((e && (e.message || e)) || e);
}

// ── JSON API Endpoints ─────────────────────────────────────────────────

// Destinations
app.get('/api/destinations', async (_req, res) => {
  try { res.json(await listDestinations()); } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.post('/api/destinations', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim();
    if (!email) return res.status(400).json({ error: 'email required' });
    res.json(await createDestination(email));
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.delete('/api/destinations/:id', async (req, res) => {
  try { await deleteDestination(req.params.id); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Domains
app.get('/api/domains', async (_req, res) => {
  try { res.json(await listDomains()); } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Workers
app.get('/api/workers', async (_req, res) => {
  try { res.json(await listWorkers()); } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Rules
app.get('/api/rules', async (req, res) => {
  try { res.json(await listRules(req.query.zoneId)); } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.post('/api/rules', async (req, res) => {
  try {
    const customEmail = String(req.body.customEmail || '').trim();
    let destInput = String(req.body.destinationIdManual || '').trim();
    if (!destInput) destInput = String(req.body.destinationId || '').trim();
    const type = String(req.body.type || 'forward').trim();
    const zoneId = String(req.body.zoneId || '').trim();
    if (!customEmail) return res.status(400).json({ error: 'customEmail required' });
    if (type !== 'drop' && !destInput) return res.status(400).json({ error: 'destination required' });
    res.json(await createRule(customEmail, destInput, type, zoneId || null));
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.put('/api/rules/:id', async (req, res) => {
  try {
    const customEmail = String(req.body.customEmail || '').trim();
    const destinationId = String(req.body.destinationId || '').trim();
    const type = req.body.type ? String(req.body.type).trim() : undefined;
    const enabledVal = String(req.body.enabled ?? '').toLowerCase();
    const enabled = enabledVal === 'true' ? true : enabledVal === 'false' ? false : undefined;
    const zoneId = String(req.body.zoneId || '').trim();
    res.json(await updateRule(req.params.id, { customEmail, destinationId, enabled, type, zoneId: zoneId || null }));
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.delete('/api/rules/:id', async (req, res) => {
  try {
    const zoneId = String(req.body?.zoneId || req.query.zoneId || '').trim();
    await deleteRule(req.params.id, zoneId || null);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Inbox
app.get('/api/inbox/summary', async (_req, res) => {
  try {
    const sql = `
      SELECT
        LOWER(recipient) AS recipient,
        MAX(created_at) AS latest_at,
        MIN(created_at) AS first_at,
        COUNT(*) AS total
      FROM emails
      WHERE recipient IS NOT NULL AND TRIM(recipient) != ''
      GROUP BY LOWER(recipient)
    `;
    res.json(await queryD1(sql));
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

app.get('/api/inbox', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const recipient = String(req.query.recipient || '').trim().toLowerCase();
    let sql = `SELECT id, sender, recipient, subject, created_at FROM emails`;
    const params = [];
    if (recipient) { sql += ` WHERE LOWER(recipient) = ?`; params.push(recipient); }
    sql += ` ORDER BY id DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    res.json(await queryD1(sql, params));
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.get('/api/inbox/:id', async (req, res) => {
  try {
    const sql = `SELECT * FROM emails WHERE id = ?`;
    const rows = await queryD1(sql, [req.params.id]);
    if (!rows || !rows.length) return res.status(404).json({ error: 'Message not found' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});
app.delete('/api/inbox/:id', async (req, res) => {
  try { await queryD1(`DELETE FROM emails WHERE id = ?`, [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Init DB
app.post('/api/inbox/init', async (_req, res) => {
  try {
    const schemaPath = path.join(__dirname, 'worker', 'schema.sql');
    const sql = fs.readFileSync(schemaPath, 'utf8');
    await queryD1(sql);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Configuration
app.get('/api/config', (_req, res) => {
  res.json({
    account_id: process.env.CLOUDFLARE_ACCOUNT_ID || '',
    zone_id: process.env.CLOUDFLARE_ZONE_ID || '',
    d1_database_id: process.env.CLOUDFLARE_D1_DATABASE_ID || '',
    has_token: !!process.env.CLOUDFLARE_API_TOKEN
  });
});

app.post('/api/config', (req, res) => {
  const { account_id, zone_id, api_token, d1_database_id } = req.body;
  const accountVal = sanitizeEnvValue('account_id', account_id);
  if (accountVal.error) return res.status(400).json({ error: accountVal.error });
  const zoneVal = sanitizeEnvValue('zone_id', zone_id);
  if (zoneVal.error) return res.status(400).json({ error: zoneVal.error });
  const d1Val = sanitizeEnvValue('d1_database_id', d1_database_id);
  if (d1Val.error) return res.status(400).json({ error: d1Val.error });
  const tokenVal = sanitizeEnvValue('api_token', api_token);
  if (tokenVal.error) return res.status(400).json({ error: tokenVal.error });

  if (accountVal.value !== undefined) process.env.CLOUDFLARE_ACCOUNT_ID = accountVal.value;
  if (zoneVal.value !== undefined) process.env.CLOUDFLARE_ZONE_ID = zoneVal.value;
  if (d1Val.value !== undefined) process.env.CLOUDFLARE_D1_DATABASE_ID = d1Val.value;
  if (tokenVal.value) process.env.CLOUDFLARE_API_TOKEN = tokenVal.value;

  try {
    const envPath = path.join(__dirname, '.env');
    let content = '';
    if (fs.existsSync(envPath)) content = fs.readFileSync(envPath, 'utf8');
    const updateKey = (key, val) => {
      const regex = new RegExp(`^${key}=.*`, 'm');
      if (regex.test(content)) content = content.replace(regex, `${key}=${val}`);
      else content += `\n${key}=${val}`;
    };
    if (accountVal.value !== undefined) updateKey('CLOUDFLARE_ACCOUNT_ID', accountVal.value);
    if (zoneVal.value !== undefined) updateKey('CLOUDFLARE_ZONE_ID', zoneVal.value);
    if (d1Val.value !== undefined) updateKey('CLOUDFLARE_D1_DATABASE_ID', d1Val.value);
    if (tokenVal.value) updateKey('CLOUDFLARE_API_TOKEN', tokenVal.value);
    fs.writeFileSync(envPath, content.trim() + '\n');
    updateCfToken();
    resetDomainCache();
    resetWorkerCache();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Catch-all
app.post('/api/catch-all', async (req, res) => {
  try {
    const action = String(req.body.action || '').trim();
    const destinationId = String(req.body.destinationId || '').trim();
    let body;
    if (action === 'disabled') body = { enabled: false };
    else if (action === 'drop') body = { enabled: true, action: { type: 'drop' } };
    else if (action === 'forward' || action === 'forward_to') {
      if (!destinationId) return res.status(400).json({ error: 'destination required for forward' });
      const value = await resolveDestinationArray(destinationId);
      body = { enabled: true, action: { type: 'forward', value } };
    } else return res.status(400).json({ error: 'unknown action' });
    const resp = await cf.put(`/zones/${process.env.CLOUDFLARE_ZONE_ID}/email/routing/rules/catch_all`, body);
    if (!resp.data || !resp.data.success) throw new Error(JSON.stringify(resp.data && (resp.data.errors || resp.data)));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Health
app.get('/healthz', (_req, res) => {
  res.status(200).json({ ok: true });
});

app.get('/health', async (_req, res) => {
  const warnings = [];
  let destinations = 0;
  let rules = 0;
  try {
    const d = await listDestinations();
    destinations = d.length;
  } catch (e) {
    warnings.push('destinations: ' + eToMessage(e));
  }
  try {
    const r = await listRules();
    rules = r.length;
  } catch (e) {
    warnings.push('rules: ' + eToMessage(e));
  }
  const ok = warnings.length === 0;
  res.status(ok ? 200 : 200).json({ ok, destinations, rules, warnings });
});

// Diagnostics — probe each Cloudflare capability and report missing permissions
app.get('/api/diagnostics', async (_req, res) => {
  const checks = [];
  const probe = async (name, fn) => {
    try {
      const result = await fn();
      checks.push({ name, ok: true, detail: typeof result === 'number' ? `${result} item(s)` : 'ok' });
    } catch (e) {
      const msg = eToMessage(e);
      const missingPerm = /Authentication error|10000/.test(msg);
      checks.push({
        name,
        ok: false,
        detail: msg,
        hint: missingPerm
          ? "Token missing required permission. Add 'Email Routing' (Edit) for Account and Zone in the Cloudflare dashboard."
          : undefined,
      });
    }
  };

  await probe('token_verify', async () => {
    const r = await cf.get('/user/tokens/verify');
    return r.data.success ? 1 : 0;
  });
  await probe('destinations', async () => (await listDestinations()).length);
  await probe('rules', async () => (await listRules()).length);
  await probe('domains', async () => (await listDomains()).length);
  await probe('d1', async () => {
    const rows = await queryD1('SELECT name FROM sqlite_master WHERE type=\'table\'');
    return rows.length;
  });

  const allOk = checks.every((c) => c.ok);
  res.json({ ok: allOk, checks });
});

// ── Password management (set via API, for initial setup) ───────────────
app.post('/api/setup-password', rateLimit('setup-password', 5), (req, res) => {
  const password = String(req.body?.password || '').trim();
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password minimal 8 karakter' });
  }
  // Only allow if password not yet configured
  if (isPasswordConfigured()) {
    return res.status(400).json({ error: 'Password already configured. Edit .env directly to change.' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  try {
    const envPath = path.join(__dirname, '.env');
    let content = '';
    if (fs.existsSync(envPath)) content = fs.readFileSync(envPath, 'utf8');
    const updateKey = (key, val) => {
      const regex = new RegExp(`^${key}=.*`, 'm');
      if (regex.test(content)) content = content.replace(regex, `${key}=${val}`);
      else content += `\n${key}=${val}`;
    };
    updateKey('PASSWORD_SALT', salt);
    updateKey('PASSWORD_HASH', hash);
    fs.writeFileSync(envPath, content.trim() + '\n');
    process.env.PASSWORD_SALT = salt;
    process.env.PASSWORD_HASH = hash;
    res.json({ ok: true, message: 'Password berhasil diset!' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Static files ───────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get(/^(?!\/api)(?!\/health).*/, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Email Routing Panel listening on http://localhost:${PORT}`);
  if (!isPasswordConfigured()) {
    console.log('[INFO] Password not configured. Visit the panel to set up a password.');
  }
});