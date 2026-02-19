/**
 * Cloudflare Email Routing Panel — API server (Express + Axios)
 * Serves static UI from /public and exposes JSON endpoints under /api
 */

const express = require('express');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.disable('x-powered-by');
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
// Minimal request logger to help diagnose routing issues
app.use((req, _res, next) => { try { console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`); } catch {} finally { next(); } });

const PORT = process.env.PORT || 3000;

if (!process.env.CF_API_TOKEN || !process.env.CF_ACCOUNT_ID || !process.env.CF_ZONE_ID) {
  console.warn('[WARN] Missing .env: CF_API_TOKEN, CF_ACCOUNT_ID, CF_ZONE_ID. Please configure via Settings.');
}
if (!process.env.CF_D1_DATABASE_ID) {
  console.warn('[WARN] Missing .env: CF_D1_DATABASE_ID. Inbox features will be disabled.');
}

const cf = axios.create({
  baseURL: 'https://api.cloudflare.com/client/v4',
  headers: { Authorization: `Bearer ${process.env.CF_API_TOKEN || ''}` }
});

function updateCfToken() {
  cf.defaults.headers['Authorization'] = `Bearer ${process.env.CF_API_TOKEN || ''}`;
}

const speakeasy = require('speakeasy');

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const PASSWORD_SESSION_TTL_MS = TOKEN_TTL_MS;
const REGISTER_REQUEST_TTL_MS = 10 * 60 * 1000;
const REGISTER_REQUEST_FILE = path.join(__dirname, '.register-request.json');
const DOMAIN_CACHE_TTL_MS = 5 * 60 * 1000;
const domainCache = { data: null, expiresAt: 0 };
const WORKER_CACHE_TTL_MS = 5 * 60 * 1000;
const workerCache = { data: null, expiresAt: 0 };
const COOKIE_AUTH_TOKEN = 'auth_token';
const COOKIE_SESSION_ID = 'session_id';
const COOKIE_PASSWORD_SESSION_ID = 'pwd_session_id';
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const RATE_LIMIT_MAX = 10;

const verifiedSessions = new Map();
const passwordSessions = new Map();

function readRegisterStore() {
  try {
    if (fs.existsSync(REGISTER_REQUEST_FILE)) {
      return JSON.parse(fs.readFileSync(REGISTER_REQUEST_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Error reading register request file:', e);
  }
  return { pending: null };
}

function writeRegisterStore(store) {
  try {
    fs.writeFileSync(REGISTER_REQUEST_FILE, JSON.stringify(store, null, 2) + '\n');
  } catch (e) {
    console.error('Error writing register request file:', e);
  }
}

function getPendingRegisterRequest() {
  const store = readRegisterStore();
  const pending = store && store.pending;
  if (!pending) return null;
  if (pending.expiresAt && Date.now() > pending.expiresAt) {
    store.pending = null;
    writeRegisterStore(store);
    return null;
  }
  return pending;
}

function setPendingRegisterRequest(request) {
  const store = readRegisterStore();
  store.pending = request;
  writeRegisterStore(store);
  return request;
}

function sendTelegramMessage(message) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_MASTER_ID;
  if (!botToken || !chatId) return;
  const payload = JSON.stringify({ chat_id: chatId, text: message });
  const req = https.request(
    {
      hostname: 'api.telegram.org',
      method: 'POST',
      path: `/bot${botToken}/sendMessage`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 5000,
    },
    (res) => {
      res.on('data', () => {});
    }
  );
  req.on('error', () => {});
  req.write(payload);
  req.end();
}

function resetDomainCache() {
  domainCache.data = null;
  domainCache.expiresAt = 0;
}

function resetWorkerCache() {
  workerCache.data = null;
  workerCache.expiresAt = 0;
}

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

const rateLimitStore = new Map();

function rateLimit(keyPrefix, max = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW_MS) {
  return (req, res, next) => {
    const key = `${keyPrefix}:${req.ip}`;
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, start: now };
    if (now - entry.start > windowMs) {
      entry.count = 0;
      entry.start = now;
    }
    entry.count += 1;
    rateLimitStore.set(key, entry);
    if (entry.count > max) {
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    return next();
  };
}

function getEnvVariable(key) {
  try {
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
      const content = fs.readFileSync(envPath, 'utf8');
      const match = content.match(new RegExp(`^${key}=(.*)$`, 'm'));
      return match ? match[1].trim() : null;
    }
  } catch (e) {
    console.error('Error reading .env file:', e);
  }
  return process.env[key];
}

function sanitizeEnvValue(label, value) {
  if (value === undefined) return { value: undefined };
  const text = String(value);
  if (/[\r\n\0]/.test(text)) {
    return { error: `${label} contains invalid characters` };
  }
  if (text.length > 512) {
    return { error: `${label} is too long` };
  }
  return { value: text.trim() };
}

const getAccessToken = () => getEnvVariable('ACCESS_TOKEN');
const getAccessTokenTimestamp = () => getEnvVariable('ACCESS_TOKEN_TIMESTAMP');
const getAccessTokenExpiresAt = () => getEnvVariable('ACCESS_TOKEN_EXPIRES_AT');
const getTfaSecret = () => getEnvVariable('TFA_SECRET');
const getTfaSecretExpiresAt = () => getEnvVariable('TFA_SECRET_EXPIRES_AT');
const getPasswordHash = () => getEnvVariable('PASSWORD_HASH');
const getPasswordSalt = () => getEnvVariable('PASSWORD_SALT');
const getAllowUnauthenticated = () => {
  const raw = String(getEnvVariable('ALLOW_UNAUTHENTICATED') || '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes';
};

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
  try {
    return Buffer.from(trimmed, 'base64');
  } catch {
    return null;
  }
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
  } catch {
    return false;
  }
}

function getAccessTokenMaxAgeMs() {
  const expiresAt = parseInt(getAccessTokenExpiresAt(), 10);
  if (Number.isFinite(expiresAt)) return Math.max(0, expiresAt - Date.now());
  const timestamp = parseInt(getAccessTokenTimestamp(), 10);
  if (Number.isFinite(timestamp)) {
    return Math.max(0, timestamp + TOKEN_TTL_MS - Date.now());
  }
  return TOKEN_TTL_MS;
}

function setAuthTokenCookie(res) {
  const accessToken = getAccessToken();
  if (!accessToken) return;
  const cookie = serializeCookie(COOKIE_AUTH_TOKEN, accessToken, {
    ...getCookieOptions(),
    maxAge: getAccessTokenMaxAgeMs(),
  });
  appendSetCookie(res, cookie);
}

function setSessionCookie(res, sessionId, expiresAt) {
  if (!sessionId) return;
  const maxAge = expiresAt ? Math.max(0, expiresAt - Date.now()) : TOKEN_TTL_MS;
  const cookie = serializeCookie(COOKIE_SESSION_ID, sessionId, {
    ...getCookieOptions(),
    maxAge,
  });
  appendSetCookie(res, cookie);
}

function setPasswordSessionCookie(res, sessionId, expiresAt) {
  if (!sessionId) return;
  const maxAge = expiresAt ? Math.max(0, expiresAt - Date.now()) : PASSWORD_SESSION_TTL_MS;
  const cookie = serializeCookie(COOKIE_PASSWORD_SESSION_ID, sessionId, {
    ...getCookieOptions(),
    maxAge,
  });
  appendSetCookie(res, cookie);
}

function clearAuthCookies(res) {
  const opts = { ...getCookieOptions(), maxAge: 0 };
  appendSetCookie(res, serializeCookie(COOKIE_AUTH_TOKEN, '', opts));
  appendSetCookie(res, serializeCookie(COOKIE_SESSION_ID, '', opts));
  appendSetCookie(res, serializeCookie(COOKIE_PASSWORD_SESSION_ID, '', opts));
}

function clearCookie(res, name) {
  const opts = { ...getCookieOptions(), maxAge: 0 };
  appendSetCookie(res, serializeCookie(name, '', opts));
}

if (!getAccessToken()) {
  console.warn('[WARN] Missing .env: ACCESS_TOKEN. The application will not be secured.');
}

app.post('/api/login', rateLimit('login'), (req, res) => {
  if (getPendingRegisterRequest()) {
    return res.status(403).json({ error: 'Registration pending approval' });
  }
  const { token } = req.body;
  const accessToken = getAccessToken();

  if (!accessToken) {
    clearAuthCookies(res);
    return res.status(400).json({ error: 'Access key not configured' });
  }

  if (token === accessToken) {
    if (isAccessTokenExpired()) {
      clearAuthCookies(res);
      return res.status(401).json({ error: 'Token expired' });
    }
    clearCookie(res, COOKIE_SESSION_ID);
    setAuthTokenCookie(res);
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/api/login-password', rateLimit('login-password'), (req, res) => {
  if (getPendingRegisterRequest()) {
    return res.status(403).json({ error: 'Registration pending approval' });
  }
  if (!isPasswordConfigured()) {
    return res.status(400).json({ error: 'Password not configured' });
  }
  const password = String(req.body?.password || '').trim();
  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }
  if (!verifyPasswordInput(password)) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  const sessionId = crypto.randomBytes(16).toString('hex');
  const expiresAt = Date.now() + PASSWORD_SESSION_TTL_MS;
  passwordSessions.set(sessionId, expiresAt);
  clearCookie(res, COOKIE_AUTH_TOKEN);
  clearCookie(res, COOKIE_SESSION_ID);
  setPasswordSessionCookie(res, sessionId, expiresAt);
  res.json({ ok: true });
});

function isAccessTokenExpired() {
  const tokenExpiresAt = parseInt(getAccessTokenExpiresAt(), 10);
  if (Number.isFinite(tokenExpiresAt)) {
    return Date.now() > tokenExpiresAt;
  }
  const tokenTimestamp = getAccessTokenTimestamp();
  if (!tokenTimestamp) return false;
  const tokenAge = Date.now() - parseInt(tokenTimestamp, 10);
  return tokenAge > TOKEN_TTL_MS;
}

function isTfaSecretExpired() {
  const tfaExpiresAt = parseInt(getTfaSecretExpiresAt(), 10);
  if (Number.isFinite(tfaExpiresAt)) {
    return Date.now() > tfaExpiresAt;
  }
  return false;
}

function getSessionExpiresAt() {
  const tfaExpiresAt = parseInt(getTfaSecretExpiresAt(), 10);
  if (Number.isFinite(tfaExpiresAt)) {
    return tfaExpiresAt;
  }
  return Date.now() + TOKEN_TTL_MS;
}

app.get('/api/auth-status', (_req, res) => {
  const accessToken = getAccessToken();
  const pending = getPendingRegisterRequest();
  const passwordEnabled = isPasswordConfigured();
  const authConfigured = !!accessToken || !!getTfaSecret() || passwordEnabled;
  const allowUnauth = getAllowUnauthenticated();
  res.json({
    accessTokenEnabled: !!accessToken,
    tokenExpired: !!accessToken && isAccessTokenExpired(),
    tfaEnabled: !!getTfaSecret(),
    tfaExpired: !!getTfaSecret() && isTfaSecretExpired(),
    passwordEnabled,
    authConfigured,
    authRequired: !allowUnauth,
    registerPending: !!pending,
    registerExpiresAt: pending ? pending.expiresAt : null,
  });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie || '');
  const sessionId = cookies[COOKIE_SESSION_ID];
  const passwordSessionId = cookies[COOKIE_PASSWORD_SESSION_ID];
  if (sessionId) verifiedSessions.delete(sessionId);
  if (passwordSessionId) passwordSessions.delete(passwordSessionId);
  clearAuthCookies(res);
  res.json({ ok: true });
});

app.post('/api/register-request', (req, res) => {
  const pending = getPendingRegisterRequest();
  if (pending) {
    return res.status(429).json({ error: 'Register request already pending', expiresAt: pending.expiresAt });
  }
  const request = {
    id: crypto.randomBytes(3).toString('hex'),
    requestedAt: Date.now(),
    expiresAt: Date.now() + REGISTER_REQUEST_TTL_MS,
    ip: req.ip,
    userAgent: req.headers['user-agent'] || '',
  };
  setPendingRegisterRequest(request);
  sendTelegramMessage(
    [
      'Panel register request received.',
      `ID: ${request.id}`,
      `IP: ${request.ip}`,
      `Expires in 10 minutes.`,
      'Approve with /register 5m (default 5m).',
    ].join('\n')
  );
  res.json({ ok: true, expiresAt: request.expiresAt });
});

app.post('/api/verify-2fa', rateLimit('verify-2fa'), (req, res) => {
  if (getPendingRegisterRequest()) {
    return res.status(403).json({ error: 'Registration pending approval' });
  }
  const { token } = req.body;
  const secret = getTfaSecret();

  if (!secret) {
    return res.status(400).json({ error: '2FA not configured' });
  }
  if (isTfaSecretExpired()) {
    clearAuthCookies(res);
    return res.status(401).json({ error: '2FA expired' });
  }

  const normalizedToken = String(token || '').replace(/\s+/g, '');
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: normalizedToken,
    window: 1,
  });

  if (verified) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const expiresAt = getSessionExpiresAt();
    verifiedSessions.set(sessionId, expiresAt);
    clearCookie(res, COOKIE_AUTH_TOKEN);
    setSessionCookie(res, sessionId, expiresAt);
    res.json({ ok: true });
  } else {
    res.status(401).json({ error: 'Invalid 2FA token' });
  }
});

const authMiddleware = (req, res, next) => {
  if (getPendingRegisterRequest()) {
    return res.status(403).json({ error: 'Registration pending approval' });
  }
  const accessToken = getAccessToken();
  const tfaSecret = getTfaSecret();
  const passwordConfigured = isPasswordConfigured();
  const allowUnauth = getAllowUnauthenticated();
  if (!accessToken && !tfaSecret && !passwordConfigured) {
    if (allowUnauth) return next();
    return res.status(401).json({ error: 'Authentication not configured' });
  }
  const cookies = parseCookies(req.headers.cookie || '');
  const token = req.headers.authorization?.split(' ')[1] || cookies[COOKIE_AUTH_TOKEN];
  const sessionId = req.headers['x-session-id'] || cookies[COOKIE_SESSION_ID];
  const passwordSessionId = cookies[COOKIE_PASSWORD_SESSION_ID];

  let tokenExpired = false;
  let tokenOk = false;
  if (token && token === accessToken) {
    if (isAccessTokenExpired()) tokenExpired = true;
    else tokenOk = true;
  }

  let sessionOk = false;
  if (tfaSecret && !isTfaSecretExpired() && sessionId && verifiedSessions.has(sessionId)) {
    const expiresAt = verifiedSessions.get(sessionId);
    if (!expiresAt || Date.now() <= expiresAt) {
      sessionOk = true;
    } else {
      verifiedSessions.delete(sessionId);
      clearCookie(res, COOKIE_SESSION_ID);
    }
  }

  let passwordOk = false;
  if (passwordConfigured && passwordSessionId && passwordSessions.has(passwordSessionId)) {
    const expiresAt = passwordSessions.get(passwordSessionId);
    if (!expiresAt || Date.now() <= expiresAt) {
      passwordOk = true;
    } else {
      passwordSessions.delete(passwordSessionId);
      clearCookie(res, COOKIE_PASSWORD_SESSION_ID);
    }
  }

  if (tokenOk || sessionOk || passwordOk) {
    return next();
  }
  if (tokenExpired) {
    clearCookie(res, COOKIE_AUTH_TOKEN);
    return res.status(401).json({ error: 'Token expired' });
  }
  if (tfaSecret && isTfaSecretExpired()) {
    clearCookie(res, COOKIE_SESSION_ID);
    return res.status(401).json({ error: '2FA expired' });
  }
  if (tfaSecret && !accessToken && !passwordConfigured) {
    return res.status(401).json({ error: '2FA not verified' });
  }
  return res.status(401).json({ error: 'Unauthorized' });
};

app.use('/api', authMiddleware);

app.get('/api/session', (_req, res) => {
  res.json({ ok: true });
});

// ------------- CF helpers -------------
async function listDestinations() {
  const res = await cf.get(`/accounts/${process.env.CF_ACCOUNT_ID}/email/routing/addresses`, { params: { per_page: 100 } });
  return res.data.result || [];
}
async function createDestination(email) {
  const res = await cf.post(`/accounts/${process.env.CF_ACCOUNT_ID}/email/routing/addresses`, { email });
  return res.data.result;
}
async function deleteDestination(id) {
  const res = await cf.delete(`/accounts/${process.env.CF_ACCOUNT_ID}/email/routing/addresses/${id}`);
  return res.data.result;
}
async function listRules(zoneId = process.env.CF_ZONE_ID) {
  if (!zoneId) throw new Error('CF_ZONE_ID not configured');
  const res = await cf.get(`/zones/${zoneId}/email/routing/rules`, { params: { per_page: 100 } });
  return res.data.result || [];
}
async function getRule(ruleId, zoneId = process.env.CF_ZONE_ID) {
  if (!zoneId) throw new Error('CF_ZONE_ID not configured');
  const res = await cf.get(`/zones/${zoneId}/email/routing/rules/${ruleId}`);
  return res.data.result;
}
async function createRule(customEmail, destinationInput, type = 'forward', zoneIdOverride = null) {
  const zoneId = zoneIdOverride || process.env.CF_ZONE_ID;
  if (!zoneId) throw new Error('CF_ZONE_ID not configured');
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
  const targetZoneId = zoneId || process.env.CF_ZONE_ID;
  if (!targetZoneId) throw new Error('CF_ZONE_ID not configured');
  const current = await getRule(ruleId, targetZoneId);
  let actions = current.actions;
  
  // Handle type/destination updates
  const targetType = type || (actions[0] && actions[0].type) || 'forward';
  if (type || destinationId) {
    if (targetType === 'drop') {
      actions = [{ type: 'drop' }];
    } else if (targetType === 'worker') {
      const val = destinationId || (actions[0] && actions[0].value && actions[0].value[0]);
      if (val) actions = [{ type: 'worker', value: [val] }];
    } else {
      // forward
      const val = destinationId || (actions[0] && actions[0].value && actions[0].value[0]);
      if (val && destinationId) { // Only resolve if explicitly updating destination
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
  const zoneId = zoneIdOverride || process.env.CF_ZONE_ID;
  if (!zoneId) throw new Error('CF_ZONE_ID not configured');
  const res = await cf.delete(`/zones/${zoneId}/email/routing/rules/${ruleId}`);
  return res.data.result;
}

async function resolveDestinationArray(input) {
  if (!input) throw new Error('destination required');
  if (/@/.test(input)) return [String(input).trim().toLowerCase()];
  const r = await cf.get(`/accounts/${process.env.CF_ACCOUNT_ID}/email/routing/addresses/${input}`);
  if (!r.data || !r.data.result || !r.data.result.email) throw new Error('destination not found: ' + input);
  if (r.data.result.verified === false) throw new Error('destination not verified: ' + r.data.result.email);
  return [String(r.data.result.email).trim().toLowerCase()];
}

async function listDomains() {
  if (domainCache.data && domainCache.expiresAt > Date.now()) {
    return domainCache.data;
  }
  if (!process.env.CF_API_TOKEN) throw new Error('CF_API_TOKEN not configured');
  const params = { per_page: 50, page: 1 };
  if (process.env.CF_ACCOUNT_ID) params['account.id'] = process.env.CF_ACCOUNT_ID;
  const results = [];
  let page = 1;
  let totalPages = 1;
  do {
    params.page = page;
    const res = await cf.get('/zones', { params });
    const data = res.data || {};
    const zones = data.result || [];
    zones.forEach((zone) => {
      if (zone && zone.id && zone.name) results.push({ id: zone.id, name: zone.name });
    });
    totalPages = (data.result_info && data.result_info.total_pages) || 1;
    page += 1;
  } while (page <= totalPages);
  domainCache.data = results;
  domainCache.expiresAt = Date.now() + DOMAIN_CACHE_TTL_MS;
  return results;
}

async function listWorkers() {
  if (workerCache.data && workerCache.expiresAt > Date.now()) {
    return workerCache.data;
  }
  if (!process.env.CF_API_TOKEN) throw new Error('CF_API_TOKEN not configured');
  if (!process.env.CF_ACCOUNT_ID) throw new Error('CF_ACCOUNT_ID not configured');
  const res = await cf.get(`/accounts/${process.env.CF_ACCOUNT_ID}/workers/scripts`, { params: { per_page: 100 } });
  const scripts = res.data && res.data.result ? res.data.result : [];
  const workers = scripts
    .map((script) => {
      const name = script.id || script.name || script.script || '';
      return name ? { id: name, name } : null;
    })
    .filter(Boolean);
  workerCache.data = workers;
  workerCache.expiresAt = Date.now() + WORKER_CACHE_TTL_MS;
  return workers;
}

async function queryD1(sql, params = []) {
  if (!process.env.CF_D1_DATABASE_ID) throw new Error('D1 Database ID not configured');
  if (process.env.CF_D1_DATABASE_ID.includes('REPLACE')) throw new Error('D1 Database ID is invalid (placeholder detected)');
  const res = await cf.post(`/accounts/${process.env.CF_ACCOUNT_ID}/d1/database/${process.env.CF_D1_DATABASE_ID}/query`, {
    sql,
    params
  });
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

// ------------- JSON APIs -------------
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
app.get('/api/inbox', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const recipient = String(req.query.recipient || '').trim().toLowerCase();
    let sql = `SELECT id, sender, recipient, subject, created_at FROM emails`;
    const params = [];
    if (recipient) {
      sql += ` WHERE LOWER(recipient) = ?`;
      params.push(recipient);
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
    account_id: process.env.CF_ACCOUNT_ID || '',
    zone_id: process.env.CF_ZONE_ID || '',
    d1_database_id: process.env.CF_D1_DATABASE_ID || '',
    has_token: !!process.env.CF_API_TOKEN
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

  if (accountVal.value !== undefined) process.env.CF_ACCOUNT_ID = accountVal.value;
  if (zoneVal.value !== undefined) process.env.CF_ZONE_ID = zoneVal.value;
  if (d1Val.value !== undefined) process.env.CF_D1_DATABASE_ID = d1Val.value;
  if (tokenVal.value) process.env.CF_API_TOKEN = tokenVal.value;

  try {
    const envPath = path.join(__dirname, '.env');
    let content = '';
    if (fs.existsSync(envPath)) content = fs.readFileSync(envPath, 'utf8');
    
    const updateKey = (key, val) => {
      const regex = new RegExp(`^${key}=.*`, 'm');
      if (regex.test(content)) content = content.replace(regex, `${key}=${val}`);
      else content += `\n${key}=${val}`;
    };

    if (accountVal.value !== undefined) updateKey('CF_ACCOUNT_ID', accountVal.value);
    if (zoneVal.value !== undefined) updateKey('CF_ZONE_ID', zoneVal.value);
    if (d1Val.value !== undefined) updateKey('CF_D1_DATABASE_ID', d1Val.value);
    if (tokenVal.value) updateKey('CF_API_TOKEN', tokenVal.value);

    fs.writeFileSync(envPath, content.trim() + '\n');
    updateCfToken();
    resetDomainCache();
    resetWorkerCache();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Catch‑all
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
    const resp = await cf.put(`/zones/${process.env.CF_ZONE_ID}/email/routing/rules/catch_all`, body);
    if (!resp.data || !resp.data.success) throw new Error(JSON.stringify(resp.data && (resp.data.errors || resp.data)));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: eToMessage(e) }); }
});

// Health
app.get('/health', async (_req, res) => {
  try {
    const [d, r] = await Promise.all([listDestinations(), listRules()]);
    res.json({ ok: true, destinations: d.length, rules: r.length });
  }
  catch (e) { res.status(500).json({ ok: false, error: eToMessage(e) }); }
});

// ------------- Static files -------------
app.use(express.static(path.join(__dirname, 'public')));

// Root -> SPA fallback (exclude API/health). Use RegExp to avoid path-to-regexp quirks
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get(/^(?!\/api)(?!\/health).*/, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Email Routing Panel listening on http://localhost:${PORT}`);
});
