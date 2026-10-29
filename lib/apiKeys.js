'use strict';

/**
 * API key store for the REST API.
 *
 * - Keys are generated once and only their SHA-256 hash is persisted.
 * - The plaintext key is returned exactly once on creation.
 * - Records live in DATA_DIR/api-keys.json with mode 0600.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, '..', 'data');
const FILE_PATH = path.join(DATA_DIR, 'api-keys.json');
const KEY_PREFIX = 'cfm_';

const ALL_SCOPES = [
  'rules:read',
  'rules:write',
  'destinations:read',
  'destinations:write',
  'inbox:read',
  'inbox:write',
  'domains:read',
  'config:read',
  'config:write',
  'keys:read',
  'keys:write',
  '*',
];

let cache = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function load() {
  if (cache) return cache;
  ensureDataDir();
  try {
    if (!fs.existsSync(FILE_PATH)) {
      cache = [];
      return cache;
    }
    const raw = fs.readFileSync(FILE_PATH, 'utf8').trim();
    const parsed = raw ? JSON.parse(raw) : [];
    cache = Array.isArray(parsed) ? parsed.filter((entry) => entry && entry.id && entry.hash) : [];
  } catch (error) {
    console.warn('[WARN] Could not read API key store: ' + (error && error.message));
    cache = [];
  }
  return cache;
}

function persist() {
  ensureDataDir();
  const tmpPath = FILE_PATH + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(cache, null, 2), { encoding: 'utf8', mode: 0o600 });
  fs.renameSync(tmpPath, FILE_PATH);
}

function hashKey(raw) {
  return crypto.createHash('sha256').update(String(raw)).digest('hex');
}

function isScope(value) {
  return typeof value === 'string' && ALL_SCOPES.includes(value);
}

function normalizeScopes(input) {
  const source = Array.isArray(input) ? input : [];
  const unique = Array.from(new Set(source.map((value) => String(value).trim()).filter(Boolean)));
  if (!unique.length) return ['rules:read'];
  const invalid = unique.filter((scope) => !isScope(scope));
  if (invalid.length) {
    const error = new Error('Unknown scope: ' + invalid.join(', '));
    error.status = 400;
    throw error;
  }
  if (unique.includes('*')) return ['*'];
  return unique;
}

function publicRecord(entry) {
  return {
    id: entry.id,
    name: entry.name,
    prefix: entry.prefix,
    scopes: entry.scopes,
    createdAt: entry.createdAt,
    lastUsedAt: entry.lastUsedAt || null,
  };
}

function list() {
  return load()
    .slice()
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .map(publicRecord);
}

function create({ name, scopes }) {
  const keys = load();
  const label = String(name || '').trim();
  if (!label) {
    const error = new Error('name required');
    error.status = 400;
    throw error;
  }
  if (label.length > 80) {
    const error = new Error('name is too long (max 80 characters)');
    error.status = 400;
    throw error;
  }

  const normalizedScopes = normalizeScopes(scopes);
  const raw = KEY_PREFIX + crypto.randomBytes(24).toString('base64url');
  const entry = {
    id: 'key_' + crypto.randomBytes(8).toString('hex'),
    name: label,
    prefix: raw.slice(0, 12),
    scopes: normalizedScopes,
    hash: hashKey(raw),
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
  };

  keys.push(entry);
  cache = keys;
  persist();

  return { key: raw, apiKey: publicRecord(entry) };
}

function remove(id) {
  const keyId = String(id || '').trim();
  const keys = load();
  const index = keys.findIndex((entry) => entry.id === keyId);
  if (index === -1) return false;
  keys.splice(index, 1);
  cache = keys;
  persist();
  return true;
}

function safeHashEqual(a, b) {
  const left = Buffer.from(String(a), 'hex');
  const right = Buffer.from(String(b), 'hex');
  if (left.length !== right.length || left.length === 0) return false;
  return crypto.timingSafeEqual(left, right);
}

function verify(raw) {
  if (typeof raw !== 'string' || !raw.startsWith(KEY_PREFIX)) return null;
  const digest = hashKey(raw);
  const entry = load().find((candidate) => safeHashEqual(candidate.hash, digest));
  if (!entry) return null;

  // Throttle persistence for lastUsedAt to avoid a write per request.
  const now = Date.now();
  const previous = entry.lastUsedAt ? Date.parse(entry.lastUsedAt) : 0;
  if (!previous || now - previous > 60_000) {
    entry.lastUsedAt = new Date(now).toISOString();
    try { persist(); } catch (error) {
      console.warn('[WARN] Could not update API key usage: ' + (error && error.message));
    }
  }

  return publicRecord(entry);
}

function extractKey(req) {
  const header = req.headers?.authorization || '';
  if (/^bearer\s+/i.test(header)) return header.replace(/^bearer\s+/i, '').trim();
  const apiKeyHeader = req.headers?.['x-api-key'];
  if (typeof apiKeyHeader === 'string' && apiKeyHeader.trim()) return apiKeyHeader.trim();
  return null;
}

module.exports = {
  ALL_SCOPES,
  KEY_PREFIX,
  list,
  create,
  remove,
  verify,
  extractKey,
  hashKey,
};
