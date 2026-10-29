'use strict';

/**
 * Simple password-based authentication for the panel.
 *
 * - Password is set via APP_PASSWORD (or ADMIN_PASSWORD) in .env
 * - Sessions are HMAC-signed cookies (stateless, no DB needed)
 * - 7-day session expiry
 * - Replaces Better Auth entirely
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, '..', 'data');

const SESSION_COOKIE = 'cf_panel_session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// ── Stable secret (persists across restarts) ────────────────────────────
let secret = process.env.AUTH_SECRET || process.env.BETTER_AUTH_SECRET;
if (!secret) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const secretPath = path.join(DATA_DIR, 'auth-secret.txt');
  if (fs.existsSync(secretPath)) {
    secret = fs.readFileSync(secretPath, 'utf8').trim();
  } else {
    secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretPath, secret, 'utf8');
  }
}

// ── Password from env ────────────────────────────────────────────────────
function getPassword() {
  return process.env.APP_PASSWORD || process.env.ADMIN_PASSWORD || '';
}

// ── HMAC signing ──────────────────────────────────────────────────────────
function sign(data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function createSessionToken() {
  const payload = JSON.stringify({ ts: Date.now() });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  return payloadB64 + '.' + sign(payloadB64);
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  // Use timingSafe comparison
  const expected = sign(payloadB64);
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
    if (Date.now() - payload.ts > SESSION_MAX_AGE) return null;
    return {
      user: {
        id: 'admin',
        role: 'admin',
        email: process.env.ADMIN_EMAIL || 'admin',
      },
    };
  } catch {
    return null;
  }
}

// ── Cookie helpers ─────────────────────────────────────────────────────────
function parseCookies(req) {
  const cookieHeader = req.headers?.cookie || '';
  const cookies = {};
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) cookies[k] = decodeURIComponent(v);
  }
  return cookies;
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req);
  return verifySessionToken(cookies[SESSION_COOKIE]);
}

function getCookieOptions(req) {
  const proto = req.headers['x-forwarded-proto'] || (req.connection?.encrypted ? 'https' : 'http');
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: proto === 'https',
    maxAge: SESSION_MAX_AGE,
    path: '/',
  };
}

// ── Constant-time password compare ───────────────────────────────────────
function safeEqual(a, b) {
  const left = Buffer.from(String(a ?? ''));
  const right = Buffer.from(String(b ?? ''));
  const length = Math.max(left.length, right.length, 1);
  const paddedLeft = Buffer.alloc(length);
  const paddedRight = Buffer.alloc(length);
  left.copy(paddedLeft);
  right.copy(paddedRight);
  return crypto.timingSafeEqual(paddedLeft, paddedRight) && left.length === right.length;
}

// ── Public API ─────────────────────────────────────────────────────────────
async function login(password) {
  const expected = getPassword();
  if (!expected) throw new Error('APP_PASSWORD not set in .env');
  if (!safeEqual(password, expected)) return null;
  return createSessionToken();
}

async function ensureAdmin() {
  const pwd = getPassword();
  if (!pwd) {
    console.warn(
      '[auth] APP_PASSWORD belum di-set. Tambahkan APP_PASSWORD=... di file .env lalu restart server.'
    );
    return { created: false };
  }
  console.log('[INFO] Password login siap. Login dengan password dari APP_PASSWORD.');
  return { created: true };
}

/**
 * Stub for backward compatibility with server.js code that still
 * references auth.getAuth(). Returns no-op stubs.
 */
async function getAuth() {
  const stubError = () => {
    const e = new Error('Better Auth has been replaced by simple password auth.');
    e.status = 501;
    throw e;
  };
  return {
    auth: {
      api: {
        getSession: async (opts) => {
          // Allow cookie-based session check to work via the old code path
          const cookies = parseCookies({ headers: opts?.headers || {} });
          const session = verifySessionToken(cookies[SESSION_COOKIE]);
          if (session) {
            return {
              session: { user: session.user },
              user: session.user,
            };
          }
          return null;
        },
        signOut: async () => ({}),
        listUsers: async () => ({ users: [], total: 0 }),
        createUser: stubError,
        setRole: stubError,
        banUser: stubError,
        unbanUser: stubError,
        removeUser: stubError,
        listApiKeys: async () => ({ keys: [], total: 0 }),
        createApiKey: stubError,
        deleteApiKey: stubError,
        verifyApiKey: async () => ({ valid: false }),
      },
    },
    toNodeHandler: () => (_req, res) => {
      res.status(404).json({ error: 'Auth endpoint not found' });
    },
    baseURL: process.env.AUTH_BASE_URL ||
      (process.env.CADDY_DOMAIN
        ? `https://${process.env.CADDY_DOMAIN}`
        : `http://localhost:${process.env.PORT || 3000}`),
    db: null,
    ensureAdmin,
  };
}

module.exports = {
  SESSION_COOKIE,
  SESSION_MAX_AGE,
  login,
  verifySessionToken,
  parseCookies,
  getSessionFromReq,
  getCookieOptions,
  ensureAdmin,
  getAuth,
  DATA_DIR,
};
