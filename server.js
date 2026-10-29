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

const auth = require('./lib/auth');
const apiKeys = require('./lib/apiKeys');


const app = express();
app.disable('x-powered-by');
// Caddy terminates TLS and forwards the original client address/protocol.
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));

// ── Security headers (applied to ALL responses, incl. login/logout) ─────
app.use((req, res, next) => {
  const csp = [
    "default-src 'self'",
    "script-src 'self' https://challenges.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://challenges.cloudflare.com",
    "frame-src 'self' https://challenges.cloudflare.com",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  next();
});

// ── CORS for the REST API (API-key callers, no cookies) ────────────────
app.use('/api', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-API-Key');
  res.setHeader('Access-Control-Expose-Headers', 'Retry-After');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') return res.status(204).end();
  return next();
});

// ── Turnstile captcha (toggle from .env) ───────────────────────────────
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

function turnstileConfig() {
  const flag = String(process.env.TURNSTILE_ENABLED || '').trim().toLowerCase();
  const requested = ['1', 'true', 'yes', 'on'].includes(flag);
  const siteKey = String(process.env.TURNSTILE_SITE_KEY || '').trim();
  const secretKey = String(process.env.TURNSTILE_SECRET_KEY || '').trim();
  const enabled = requested && Boolean(siteKey) && Boolean(secretKey);
  return { requested, enabled, siteKey: enabled ? siteKey : '', secretKey, misconfigured: requested && !enabled };
}

async function verifyTurnstile(token, ip) {
  const { enabled, secretKey } = turnstileConfig();
  if (!enabled) return true;
  if (!token || typeof token !== 'string') return false;
  try {
    const body = new URLSearchParams({ secret: secretKey, response: token });
    if (ip && ip !== 'unknown') body.set('remoteip', ip);
    const response = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(8000),
    });
    const data = await response.json();
    return Boolean(data && data.success);
  } catch (error) {
    console.warn('[SECURITY] Turnstile verification failed: ' + (error && error.message));
    return false;
  }
}

// ── Rate limiting & brute force protection (fail2ban style) ─────────────
const loginAttempts = new Map(); // ip -> { fails, blockCount, lastFail, blockedUntil, rateTs, rateCount }
const MAX_FAILS = 5; // max failed attempts before block
const BASE_BLOCK_MS = 15 * 60 * 1000; // first block: 15 minutes
const MAX_BLOCK_MS = 24 * 60 * 60 * 1000; // escalating cap: 24 hours
const ATTEMPT_TTL_MS = 24 * 60 * 60 * 1000; // forget an IP after a day of inactivity
const RATE_WINDOW = 60 * 1000; // 1 minute sliding window
const RATE_MAX = 5; // max login attempts per minute per IP
const FAIL_DELAY_MS = 350; // extra latency on failures to slow automation

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function blockRemainingMs(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || !entry.blockedUntil) return 0;
  const remaining = entry.blockedUntil - Date.now();
  return remaining > 0 ? remaining : 0;
}

function isLoginBlocked(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || !entry.blockedUntil) return false;
  if (Date.now() <= entry.blockedUntil) return true;
  // Block expired: let them try again, but keep escalation history for a day.
  entry.blockedUntil = 0;
  entry.fails = 0;
  return false;
}

function recordFailedLogin(ip) {
  const entry = loginAttempts.get(ip) || {
    fails: 0,
    blockCount: 0,
    rateTs: Date.now(),
    rateCount: 0,
  };
  entry.fails = (entry.fails || 0) + 1;
  entry.lastFail = Date.now();
  if (entry.fails >= MAX_FAILS) {
    entry.blockCount = (entry.blockCount || 0) + 1;
    const blockMs = Math.min(BASE_BLOCK_MS * 2 ** (entry.blockCount - 1), MAX_BLOCK_MS);
    entry.blockedUntil = Date.now() + blockMs;
    entry.fails = 0;
    const minutes = Math.round(blockMs / 60000);
    console.warn(`[SECURITY] IP ${ip} diblok — terlalu banyak login gagal. Block ${minutes} menit (level ${entry.blockCount}).`);
  } else {
    console.warn(`[SECURITY] Login gagal dari ${ip} — percobaan ${entry.fails}/${MAX_FAILS}.`);
  }
  loginAttempts.set(ip, entry);
}

function resetLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

function checkLoginRate(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { fails: 0, rateTs: now, rateCount: 0 };
  if (now - entry.rateTs > RATE_WINDOW) {
    entry.rateTs = now;
    entry.rateCount = 1;
  } else {
    entry.rateCount++;
  }
  loginAttempts.set(ip, entry);
  return entry.rateCount <= RATE_MAX;
}

function failureDelay() {
  return new Promise((resolve) => setTimeout(resolve, FAIL_DELAY_MS + Math.floor(Math.random() * 250)));
}

// Periodic cleanup to avoid an unbounded map.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    const last = Math.max(entry.lastFail || 0, entry.blockedUntil || 0, entry.rateTs || 0);
    if (now - last > ATTEMPT_TTL_MS) loginAttempts.delete(ip);
  }
}, 10 * 60 * 1000).unref();

if (turnstileConfig().misconfigured) {
  console.warn('[WARN] TURNSTILE_ENABLED aktif tetapi TURNSTILE_SITE_KEY / TURNSTILE_SECRET_KEY belum lengkap. Captcha dimatikan.');
}

// ── Simple password auth (login / logout) ───────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ip = getClientIp(req);

  // 1. Check if IP is blocked (fail2ban)
  if (isLoginBlocked(ip)) {
    const remaining = Math.ceil(blockRemainingMs(ip) / 1000 / 60);
    res.setHeader('Retry-After', String(Math.max(1, Math.ceil(blockRemainingMs(ip) / 1000))));
    return res.status(429).json({
      error: `Terlalu banyak percobaan gagal. Coba lagi dalam ${Math.max(1, remaining)} menit.`,
    });
  }

  // 2. Rate limit: max 5 attempts per minute
  if (!checkLoginRate(ip)) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: 'Terlalu cepat. Tunggu sebentar sebelum mencoba lagi.',
    });
  }

  try {
    // 3. Turnstile (optional, enabled via .env)
    const turnstile = turnstileConfig();
    if (turnstile.enabled) {
      const captchaToken = String(req.body?.turnstileToken || '');
      if (!captchaToken) {
        return res.status(400).json({ error: 'Captcha token required.' });
      }
      const captchaOk = await verifyTurnstile(captchaToken, ip);
      if (!captchaOk) {
        recordFailedLogin(ip);
        await failureDelay();
        return res.status(400).json({ error: 'Captcha verification failed. Please retry.' });
      }
    }

    const password = String(req.body?.password || '');
    const token = await auth.login(password);
    if (!token) {
      recordFailedLogin(ip);
      await failureDelay();
      return res.status(401).json({ error: 'Password salah.' });
    }
    resetLoginAttempts(ip);
    res.cookie(auth.SESSION_COOKIE, token, auth.getCookieOptions(req));
    logAudit('login', 'user:admin', { ip });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Login error' });
  }
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie(auth.SESSION_COOKIE, { path: '/' });
  res.json({ ok: true });
});
app.use((req, _res, next) => {
  try { console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`); } catch {} finally { next(); }
});

const PORT = process.env.PORT || 3000;

if (!process.env.CLOUDFLARE_API_TOKEN || !process.env.CLOUDFLARE_ACCOUNT_ID) {
  console.warn('[WARN] Missing .env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID. Configure via Settings.');
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

function getAdminApiToken() {
  const v = process.env.ADMIN_API_TOKEN;
  return v && v.trim() ? v.trim() : null;
}

// ── Cache ──────────────────────────────────────────────────────────────
const DOMAIN_CACHE_TTL_MS = 5 * 60 * 1000;
const domainCache = { data: null, expiresAt: 0 };
const WORKER_CACHE_TTL_MS = 5 * 60 * 1000;
const workerCache = { data: null, expiresAt: 0 };

function resetDomainCache() { domainCache.data = null; domainCache.expiresAt = 0; }
function resetWorkerCache() { workerCache.data = null; workerCache.expiresAt = 0; }

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

// ── Auth endpoints (Better Auth backed) ─────────────────────────────────
// Session + auth state for the SPA.
app.get('/api/auth-status', (req, res) => {
  const session = auth.getSessionFromReq(req);
  const passwordEnabled = !!(process.env.APP_PASSWORD || process.env.ADMIN_PASSWORD);
  const turnstile = turnstileConfig();
  const body = {
    authRequired: true,
    passwordEnabled,
    turnstileEnabled: turnstile.enabled,
    turnstileSiteKey: turnstile.siteKey,
  };
  if (session) {
    return res.json({ ...body, loggedIn: true, role: session.user.role });
  }
  return res.json({ ...body, loggedIn: false });
});

// Compat shim for the SPA.
app.post('/api/logout', (_req, res) => {
  res.clearCookie(auth.SESSION_COOKIE, { path: '/' });
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  const session = auth.getSessionFromReq(req);
  if (!session) return res.json({ ok: false });
  return res.json({ ok: true, role: session.user.role, email: session.user.email });
});

// ── Auth resolution / middleware ────────────────────────────────────────
// A "session" is either a validated cookie session (simple password auth) or
// an API key sent as `Authorization: Bearer <key>` / `X-API-Key: <key>`.
async function resolveSession(req) {
  const session = auth.getSessionFromReq(req);
  if (session) {
    return {
      session,
      user: session.user,
      apiKey: null,
      permissions: null,
      isAdmin: true,
    };
  }

  const rawKey = apiKeys.extractKey(req);
  if (!rawKey) return null;
  const apiKey = apiKeys.verify(rawKey);
  if (!apiKey) return { invalid: true };

  const permissions = Array.isArray(apiKey.scopes) ? apiKey.scopes : [];
  const isAdmin = permissions.includes('*');
  return {
    session: null,
    user: {
      id: 'api-key:' + apiKey.id,
      role: isAdmin ? 'admin' : 'api',
      email: apiKey.name,
    },
    apiKey,
    permissions,
    isAdmin,
  };
}

app.use('/api', async (req, res, next) => {
  const p = req.path;
  if (p.startsWith('/auth') || p === '/login' || p === '/logout' || p === '/auth-status' || p === '/session') {
    return next();
  }
  try {
    const a = await resolveSession(req);
    if (!a) return res.status(401).json({ error: 'Unauthorized. Please login.' });
    if (a.invalid) {
      return res.status(401).json({ error: 'Invalid or revoked API key.' });
    }
    req.auth = a;
    req.session = a.session;
    req.user = a.user;
    req.apiKey = a.apiKey;
    req.permissions = a.permissions;
    req.isAdmin = a.isAdmin;
    req.callerKey = a.apiKey ? 'api:' + a.apiKey.id : 'user:' + a.user.id;
    const scopeError = enforceScope(req);
    if (scopeError) return res.status(403).json({ error: scopeError });
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
});
// Require a specific permission scope (e.g. "accounts:read"). Admins bypass.
const requirePerm = (scope) => (req, res, next) => {
  if (req.isAdmin) return next();
  const perms = (req.permissions || []).map((x) => String(x));
  if (perms.includes(scope)) return next();
  return res.status(403).json({ error: 'Missing required API permission: ' + scope });
};

const requireAdmin = (req, res, next) => {
  if (req.isAdmin) return next();
  return res.status(403).json({ error: 'Admin only.' });
};

// API keys can hold fine-grained scopes; cookie sessions are admins.
const requireScope = (scope) => (req, res, next) => {
  if (req.isAdmin) return next();
  const perms = (req.permissions || []).map((x) => String(x));
  if (perms.includes(scope) || perms.includes('*')) return next();
  return res.status(403).json({ error: 'Missing required API permission: ' + scope });
};

// Coarse resource→scope map used to enforce fine-grained permissions for
// API-key subjects on the panel data routes. The action is derived from the
// HTTP method (safe methods read, everything else write).
const SCOPE_MAP = [
  [/^\/rules(\/|$)/, 'rules:read', 'rules:write'],
  [/^\/catch-all(\/|$)/, 'rules:read', 'rules:write'],
  [/^\/destinations(\/|$)/, 'destinations:read', 'destinations:write'],
  [/^\/inbox(\/|$)/, 'inbox:read', 'inbox:write'],
  [/^\/addresses(\/|$)/, 'inbox:read', 'inbox:write'],
  [/^\/domains(\/|$)/, 'domains:read', 'domains:read'],
  [/^\/workers(\/|$)/, 'domains:read', 'domains:read'],
  [/^\/config(\/|$)/, 'config:read', 'config:write'],
  [/^\/diagnostics(\/|$)/, 'config:read', 'config:read'],
];

// Returns an error string when the subject is not permitted for this request,
// or null when allowed. Admin sessions bypass; any other subject must hold a
// scoped API key covering the resource+action.
function enforceScope(req) {
  if (req.isAdmin) return null;
  const p = req.path;
  if (!req.apiKey) return 'Admin role or a scoped API key is required.';
  // Admin/user-management endpoints are gated by requireAdmin below.
  if (p.startsWith('/admin/') || p.startsWith('/keys')) return null;
  const perms = (req.permissions || []).map((x) => String(x));
  const write = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  for (const [re, readScope, writeScope] of SCOPE_MAP) {
    if (re.test(p)) {
      const need = write ? writeScope : readScope;
      return perms.includes(need) ? null : 'Missing required API permission: ' + need;
    }
  }
  return 'No permission mapping for ' + req.path;
}

// ── Admin: user management (stub — password-only mode) ─────────────────
app.get('/api/admin/users', requireAdmin, (_req, res) => {
  res.json({ users: [], total: 0 });
});

app.post('/api/admin/users', requireAdmin, (_req, res) => {
  res.status(501).json({ error: 'User management tidak tersedia di mode password-only.' });
});

app.post('/api/admin/users/:id/role', requireAdmin, (_req, res) => {
  res.status(501).json({ error: 'Tidak tersedia di mode password-only.' });
});

app.post('/api/admin/users/:id/active', requireAdmin, (_req, res) => {
  res.status(501).json({ error: 'Tidak tersedia di mode password-only.' });
});

app.delete('/api/admin/users/:id', requireAdmin, (_req, res) => {
  res.status(501).json({ error: 'Tidak tersedia di mode password-only.' });
});

// ── API keys (hashed at rest, plaintext shown once) ─────────────────────
app.get('/api/keys', requireScope('keys:read'), (req, res) => {
  const keys = apiKeys.list();
  const visible = req.isAdmin
    ? keys
    : keys.filter((key) => key.id === req.apiKey?.id);
  res.json({ apiKeys: visible, total: visible.length, availableScopes: apiKeys.ALL_SCOPES });
});

app.post('/api/keys', requireScope('keys:write'), (req, res) => {
  try {
    const requested = Array.isArray(req.body?.scopes) ? req.body.scopes.map(String) : [];
    const granted = req.permissions || [];
    if (!req.isAdmin) {
      const forbidden = requested.filter((scope) => scope === '*' || !granted.includes(scope));
      if (forbidden.length) {
        return res.status(403).json({
          error: 'Cannot grant scopes you do not hold: ' + forbidden.join(', '),
        });
      }
    }
    const created = apiKeys.create({ name: req.body?.name, scopes: requested });
    logAudit('api_key.create', req.callerKey, { id: created.apiKey.id, scopes: created.apiKey.scopes });
    return res.status(201).json(created);
  } catch (error) {
    return res.status(error.status || 500).json({ error: error.message || 'Could not create API key' });
  }
});

app.delete('/api/keys/:id', requireScope('keys:write'), (req, res) => {
  const keyId = String(req.params.id || '');
  if (!req.isAdmin && req.apiKey?.id !== keyId) {
    return res.status(403).json({ error: 'You can only revoke your own API key.' });
  }
  const removed = apiKeys.remove(keyId);
  if (!removed) return res.status(404).json({ error: 'API key not found.' });
  logAudit('api_key.revoke', req.callerKey, { id: keyId });
  return res.json({ ok: true });
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

async function listRules(zoneId) {
  if (!zoneId) throw new Error('zoneId is required');
  return await paginateAll(`/zones/${zoneId}/email/routing/rules`);
}

async function getRule(ruleId, zoneId) {
  if (!zoneId) throw new Error('zoneId is required');
  const res = await cf.get(`/zones/${zoneId}/email/routing/rules/${ruleId}`);
  return res.data.result;
}

async function createRule(customEmail, destinationInput, type = 'worker', zoneId) {
  if (!zoneId) throw new Error('zoneId is required');
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
  if (!zoneId) throw new Error('zoneId is required');
  const current = await getRule(ruleId, zoneId);
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
  const res = await cf.put(`/zones/${zoneId}/email/routing/rules/${ruleId}`, body);
  return res.data.result;
}

async function deleteRule(ruleId, zoneId) {
  if (!zoneId) throw new Error('zoneId is required');
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

// ── Generated address retention (7 days) ───────────────────────────────
const GENERATED_ADDRESS_RETENTION_DAYS = 7;
const GENERATED_ADDRESS_CLEANUP_MS = 60 * 1000;

async function cleanupExpiredGeneratedAddresses() {
  try {
    await queryD1(
      `DELETE FROM generated_addresses WHERE created_at <= datetime('now', ?)`,
      [`-${GENERATED_ADDRESS_RETENTION_DAYS} days`]
    );
  } catch (e) {
    console.warn('[WARN] Generated address cleanup failed: ' + eToMessage(e));
  }
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
    const type = String(req.body.type || 'worker').trim();
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

// Generated addresses (only the latest is kept visible; records expire after 7 days)
app.post('/api/addresses', async (req, res) => {
  try {
    const address = String(req.body?.address || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
      return res.status(400).json({ error: 'valid address required' });
    }
    await queryD1(
      `INSERT INTO generated_addresses (address, created_at) VALUES (?, CURRENT_TIMESTAMP)
       ON CONFLICT(address) DO UPDATE SET created_at = CURRENT_TIMESTAMP`,
      [address]
    );
    await cleanupExpiredGeneratedAddresses();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

app.get('/api/addresses/latest', async (_req, res) => {
  try {
    const rows = await queryD1(
      `SELECT address, created_at FROM generated_addresses
       WHERE created_at > datetime('now', ?)
       ORDER BY created_at DESC, id DESC LIMIT 1`,
      [`-${GENERATED_ADDRESS_RETENTION_DAYS} days`]
    );
    res.json(rows[0] || null);
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
    const recipients = String(req.query.recipients || '')
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    if (recipient) recipients.push(recipient);
    const uniqueRecipients = Array.from(new Set(recipients));
    let sql = `SELECT id, sender, recipient, subject, created_at FROM emails`;
    const params = [];
    if (uniqueRecipients.length) {
      sql += ` WHERE LOWER(recipient) IN (${uniqueRecipients.map(() => '?').join(', ')})`;
      params.push(...uniqueRecipients);
    }
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
    d1_database_id: process.env.CLOUDFLARE_D1_DATABASE_ID || '',
    has_token: !!process.env.CLOUDFLARE_API_TOKEN,
    has_admin_api_token: !!getAdminApiToken()
  });
});

app.post('/api/config', (req, res) => {
  const { account_id, api_token, d1_database_id, admin_api_token } = req.body;
  const accountVal = sanitizeEnvValue('account_id', account_id);
  if (accountVal.error) return res.status(400).json({ error: accountVal.error });
  const d1Val = sanitizeEnvValue('d1_database_id', d1_database_id);
  if (d1Val.error) return res.status(400).json({ error: d1Val.error });
  const tokenVal = sanitizeEnvValue('api_token', api_token);
  if (tokenVal.error) return res.status(400).json({ error: tokenVal.error });
  const adminTokenVal = sanitizeEnvValue('admin_api_token', admin_api_token);
  if (adminTokenVal.error) return res.status(400).json({ error: adminTokenVal.error });

  if (accountVal.value !== undefined) process.env.CLOUDFLARE_ACCOUNT_ID = accountVal.value;
  if (d1Val.value !== undefined) process.env.CLOUDFLARE_D1_DATABASE_ID = d1Val.value;
  if (tokenVal.value) process.env.CLOUDFLARE_API_TOKEN = tokenVal.value;
  if (adminTokenVal.value !== undefined) process.env.ADMIN_API_TOKEN = adminTokenVal.value;

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
    if (d1Val.value !== undefined) updateKey('CLOUDFLARE_D1_DATABASE_ID', d1Val.value);
    if (tokenVal.value) updateKey('CLOUDFLARE_API_TOKEN', tokenVal.value);
    if (adminTokenVal.value !== undefined) updateKey('ADMIN_API_TOKEN', adminTokenVal.value);
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
    const zoneId = String(req.body.zoneId || '').trim();
    if (!zoneId) return res.status(400).json({ error: 'zoneId required' });
    let body;
    if (action === 'disabled') body = { enabled: false };
    else if (action === 'drop') body = { enabled: true, action: { type: 'drop' } };
    else if (action === 'forward' || action === 'forward_to') {
      if (!destinationId) return res.status(400).json({ error: 'destination required for forward' });
      const value = await resolveDestinationArray(destinationId);
      body = { enabled: true, action: { type: 'forward', value } };
    } else if (action === 'worker') {
      const worker = destinationId || process.env.EMAIL_WORKER_NAME || 'inbox-worker';
      body = { enabled: true, action: { type: 'worker', value: [worker] } };
    } else return res.status(400).json({ error: 'unknown action' });
    const resp = await cf.put(`/zones/${zoneId}/email/routing/rules/catch_all`, body);
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
  try {
    const d = await listDestinations();
    destinations = d.length;
  } catch (e) {
    warnings.push('destinations: ' + eToMessage(e));
  }
  // Rules check without zoneId is not available in all-zones mode; domain list serves as connectivity check
  const ok = warnings.length === 0;
  res.status(200).json({ ok, destinations, warnings });
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
  await probe('rules', async () => {
    const domains = await listDomains();
    if (!domains.length) return 0;
    // Probe rules on first domain as a sample (all-zones mode)
    const domainRules = await listRules(domains[0].id);
    return domainRules.length;
  });
  await probe('domains', async () => (await listDomains()).length);
  await probe('d1', async () => {
    const rows = await queryD1('SELECT name FROM sqlite_master WHERE type=\'table\'');
    return rows.length;
  });

  const allOk = checks.every((c) => c.ok);
  res.json({ ok: allOk, checks });
});

function logAudit(action, callerKey, detail = {}) {
  const id = callerKey ? callerKey.slice(0, 16) : 'anon';
  console.log(`[AUDIT] ${new Date().toISOString()} action=${action} caller=${id} ${JSON.stringify(detail)}`);
}

// ── Static files ───────────────────────────────────────────────────────
// The React SPA (ui/) is built to ui/dist and served here. The legacy
// public/ folder remains a fallback for an un-built checkout.
const UI_DIST_DIR = path.join(__dirname, 'ui', 'dist');
const UI_INDEX_FILE = path.join(UI_DIST_DIR, 'index.html');
const LEGACY_PUBLIC_DIR = path.join(__dirname, 'public');
const HAS_UI_BUILD = fs.existsSync(UI_INDEX_FILE);
const FRONTEND_DIR = HAS_UI_BUILD ? UI_DIST_DIR : LEGACY_PUBLIC_DIR;

function sendAppShell(res) {
  return res.sendFile(HAS_UI_BUILD ? UI_INDEX_FILE : path.join(LEGACY_PUBLIC_DIR, 'index.html'));
}

// Auth gate untuk SPA: wajib punya session yang valid untuk melihat aplikasi.
app.get('/', (req, res) => {
  const session = auth.getSessionFromReq(req);
  if (session) return sendAppShell(res);
  return res.redirect('/login');
});

// Halaman login terpisah (disajikan tanpa session).
app.get('/login', (_req, res) => {
  if (HAS_UI_BUILD) return sendAppShell(res);
  return res.sendFile(path.join(LEGACY_PUBLIC_DIR, 'login.html'));
});
app.get('/login.html', (_req, res) => res.redirect('/login'));

app.use(express.static(FRONTEND_DIR, { index: false }));

app.get(/^(?!\/api)(?!\/health).*/, (_req, res) => {
  sendAppShell(res);
});


async function start() {
  try {
    const admin = await auth.ensureAdmin();
    console.log(admin.created
      ? '[INFO] Password login siap. Set APP_PASSWORD di .env.'
      : '[INFO] APP_PASSWORD belum di-set. Tambahkan APP_PASSWORD=... di .env lalu restart.');
  } catch (e) {
    console.warn('[WARN] Gagal bootstrap admin: ' + (e && e.message ? e.message : e));
  }

  app.listen(PORT, () => {
    console.log(`Email Routing Panel listening on http://localhost:${PORT}`);
    if (!process.env.APP_PASSWORD && !process.env.ADMIN_PASSWORD) {
      console.log('[INFO] Set APP_PASSWORD di .env untuk mengaktifkan login.');
    }
    cleanupExpiredGeneratedAddresses();
    if (process.env.CLOUDFLARE_D1_DATABASE_ID) {
      setInterval(cleanupExpiredGeneratedAddresses, GENERATED_ADDRESS_CLEANUP_MS).unref();
    }
  });
}

start();