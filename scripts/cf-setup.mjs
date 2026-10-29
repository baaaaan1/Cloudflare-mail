#!/usr/bin/env node
/**
 * Cloudflare setup helper.
 *
 * Commands:
 *   node scripts/cf-setup.mjs d1        Ensure the D1 database + schema exist
 *   node scripts/cf-setup.mjs worker    Generate worker/wrangler.toml and deploy the worker
 *   node scripts/cf-setup.mjs routing   Remove every literal rule and point catch-all to the worker
 *   node scripts/cf-setup.mjs all       d1 + worker + routing (default)
 *
 * Options:
 *   --worker <name>          Target worker name (default: EMAIL_WORKER_NAME or inbox-worker)
 *   --db-name <name>         D1 database name (default: EMAIL_DB_NAME or email_db)
 *   --zone <id|name>         Limit routing changes to one zone (repeatable by comma)
 *   --purge-destinations     Also delete every Email Routing destination address
 *   --dry-run                Show planned routing changes without applying them
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import axios from 'axios';
import dotenv from 'dotenv';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
dotenv.config({ path: path.join(ROOT, '.env') });

const args = process.argv.slice(2);
const command = args[0] && !args[0].startsWith('--') ? args[0] : 'all';

function hasFlag(name) {
  return args.includes(`--${name}`);
}

function getOption(name, fallback) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
}

const TOKEN = (process.env.CLOUDFLARE_API_TOKEN || '').trim();
const ACCOUNT_ID = (process.env.CLOUDFLARE_ACCOUNT_ID || '').trim();
const WORKER_NAME = getOption('worker', (process.env.EMAIL_WORKER_NAME || 'inbox-worker').trim());
const DB_NAME = getOption('db-name', (process.env.EMAIL_DB_NAME || 'email_db').trim());
const ZONE_FILTER = getOption('zone', '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const DRY_RUN = hasFlag('dry-run');
const PURGE_DESTINATIONS = hasFlag('purge-destinations');
const WORKER_DIR = path.join(ROOT, 'worker');
const SCHEMA_PATH = path.join(WORKER_DIR, 'schema.sql');
const WRANGLER_PATH = path.join(WORKER_DIR, 'wrangler.toml');

if (!TOKEN || !ACCOUNT_ID) {
  console.error('[ERROR] CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID must be set in .env');
  process.exit(1);
}

const api = axios.create({
  baseURL: 'https://api.cloudflare.com/client/v4',
  headers: { Authorization: `Bearer ${TOKEN}` },
  timeout: 60000,
});

function formatError(error) {
  const data = error.response && error.response.data;
  if (data && Array.isArray(data.errors) && data.errors.length) {
    return data.errors.map((item) => `${item.code || ''} ${item.message || ''}`.trim()).join('; ');
  }
  if (data) return JSON.stringify(data);
  return error.message || String(error);
}

async function cf(method, url, data, config = {}) {
  try {
    const response = await api.request({ method, url, data, ...config });
    return response.data;
  } catch (error) {
    const err = new Error(`${method.toUpperCase()} ${url} failed: ${formatError(error)}`);
    err.response = error.response;
    throw err;
  }
}

async function paginate(url, params = {}) {
  const results = [];
  let page = 1;
  let totalPages = 1;
  do {
    const response = await cf('get', url, undefined, {
      params: { ...params, page, per_page: params.per_page || 100 },
    });
    const body = response || {};
    results.push(...(body.result || []));
    totalPages = (body.result_info && body.result_info.total_pages) || 1;
    page += 1;
  } while (page <= totalPages);
  return results;
}

function updateEnvFile(key, value) {
  const envPath = path.join(ROOT, '.env');
  let content = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
  const line = `${key}=${value}`;
  const regex = new RegExp(`^${key}=.*$`, 'm');
  content = regex.test(content) ? content.replace(regex, line) : `${content.trim()}\n${line}`;
  fs.writeFileSync(envPath, content.trim() + '\n');
}

async function ensureD1() {
  console.log(`[d1] Looking for database "${DB_NAME}"...`);
  let databaseId = (process.env.CLOUDFLARE_D1_DATABASE_ID || '').trim();
  const databases = await paginate(`/accounts/${ACCOUNT_ID}/d1/database`);
  let database = databaseId ? databases.find((item) => item.uuid === databaseId) : null;
  if (!database) database = databases.find((item) => item.name === DB_NAME);

  if (!database) {
    console.log(`[d1] Creating database "${DB_NAME}"...`);
    const created = await cf('post', `/accounts/${ACCOUNT_ID}/d1/database`, { name: DB_NAME });
    database = created.result;
  }

  if (!database || !database.uuid) {
    throw new Error('Unable to resolve or create the D1 database.');
  }

  databaseId = database.uuid;
  updateEnvFile('CLOUDFLARE_D1_DATABASE_ID', databaseId);
  process.env.CLOUDFLARE_D1_DATABASE_ID = databaseId;
  console.log(`[d1] Using ${database.name || DB_NAME} (${databaseId})`);

  const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
  await cf('post', `/accounts/${ACCOUNT_ID}/d1/database/${databaseId}/query`, { sql: schema });
  const check = await cf('post', `/accounts/${ACCOUNT_ID}/d1/database/${databaseId}/query`, {
    sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'emails'",
  });
  const tables = (check.result && check.result[0] && check.result[0].results) || [];
  if (!tables.length) throw new Error('Schema applied but the emails table is missing.');
  console.log('[d1] Schema ready (table: emails)');
  return databaseId;
}

function writeWranglerConfig(databaseId) {
  const config = [
    `name = "${WORKER_NAME}"`,
    'main = "src/index.js"',
    'compatibility_date = "2023-10-30"',
    '',
    '[[d1_databases]]',
    'binding = "DB"',
    `database_name = "${DB_NAME}"`,
    `database_id = "${databaseId}"`,
    '',
    '[triggers]',
    'crons = ["* * * * *"]',
    '',
  ].join('\n');
  fs.writeFileSync(WRANGLER_PATH, config);
  console.log(`[worker] Wrote ${path.relative(ROOT, WRANGLER_PATH)}`);
}

async function workerExists(name) {
  const scripts = await paginate(`/accounts/${ACCOUNT_ID}/workers/scripts`);
  return scripts.some((script) => (script.id || script.name) === name);
}

async function deployWorker(databaseId) {
  writeWranglerConfig(databaseId);
  console.log(`[worker] Deploying "${WORKER_NAME}"...`);
  const result = spawnSync('npx --yes wrangler@4 deploy', [], {
    cwd: WORKER_DIR,
    shell: true,
    stdio: 'inherit',
    env: {
      ...process.env,
      CLOUDFLARE_API_TOKEN: TOKEN,
      CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    },
  });
  if (result.status !== 0) {
    throw new Error(`wrangler deploy failed with exit code ${result.status}`);
  }
  if (!(await workerExists(WORKER_NAME))) {
    throw new Error(`Worker "${WORKER_NAME}" was not found after deploy.`);
  }
  console.log(`[worker] Deployed ${WORKER_NAME}`);
}

async function resolveZones() {
  const zones = await paginate('/zones', { 'account.id': ACCOUNT_ID });
  const active = zones.filter((zone) => zone && zone.id && zone.name);
  if (!ZONE_FILTER.length) return active;
  const wanted = new Set(ZONE_FILTER.map((value) => value.toLowerCase()));
  const selected = active.filter(
    (zone) => wanted.has(zone.id.toLowerCase()) || wanted.has(zone.name.toLowerCase())
  );
  if (!selected.length) throw new Error(`No zone matched: ${ZONE_FILTER.join(', ')}`);
  return selected;
}

function isCatchAll(rule) {
  return (rule.matchers || []).some((matcher) => matcher.type === 'all');
}

async function updateCatchAll(zone) {
  const url = `/zones/${zone.id}/email/routing/rules/catch_all`;
  const body = {
    name: 'catch-all',
    enabled: true,
    matchers: [{ type: 'all' }],
    actions: [{ type: 'worker', value: [WORKER_NAME] }],
  };
  try {
    return await cf('put', url, body);
  } catch (error) {
    const fallback = { enabled: true, action: { type: 'worker', value: [WORKER_NAME] } };
    try {
      return await cf('put', url, fallback);
    } catch {
      throw error;
    }
  }
}

async function enforceRouting() {
  if (!(await workerExists(WORKER_NAME))) {
    throw new Error(`Worker "${WORKER_NAME}" does not exist. Run "worker" first.`);
  }

  const zones = await resolveZones();
  console.log(`[routing] Target worker: ${WORKER_NAME}`);
  console.log(`[routing] Zones: ${zones.map((zone) => zone.name).join(', ')}${DRY_RUN ? ' (dry run)' : ''}`);

  for (const zone of zones) {
    const rules = await paginate(`/zones/${zone.id}/email/routing/rules`);
    const removable = rules.filter((rule) => !isCatchAll(rule) && rule.id);
    console.log(`\n[${zone.name}] removing ${removable.length} rule(s), keeping catch-all`);
    for (const rule of removable) {
      const target = (rule.actions || [])
        .map((action) => `${action.type}:${(action.value || []).join(',')}`)
        .join(' ');
      console.log(`  - ${rule.id} ${rule.name || '(unnamed)'} ${target}`);
      if (!DRY_RUN) {
        await cf('delete', `/zones/${zone.id}/email/routing/rules/${rule.id}`);
      }
    }
    if (!DRY_RUN) {
      await updateCatchAll(zone);
      const catchAll = (await cf('get', `/zones/${zone.id}/email/routing/rules/catch_all`)).result;
      const action = (catchAll.actions || catchAll.action || [])[0] || {};
      const values = action.value || [];
      if (!catchAll.enabled || action.type !== 'worker' || values[0] !== WORKER_NAME) {
        throw new Error(`Catch-all verification failed for ${zone.name}: ${JSON.stringify(catchAll)}`);
      }
      console.log(`  catch-all -> worker:${WORKER_NAME} (enabled)`);
    }
  }

  if (PURGE_DESTINATIONS) {
    const addresses = await paginate(`/accounts/${ACCOUNT_ID}/email/routing/addresses`);
    console.log(`\n[destinations] removing ${addresses.length} destination(s)`);
    for (const address of addresses) {
      console.log(`  - ${address.email}`);
      if (!DRY_RUN) {
        await cf('delete', `/accounts/${ACCOUNT_ID}/email/routing/addresses/${address.id}`);
      }
    }
  }

  console.log('\n[routing] Done.');
}

async function main() {
  const valid = ['d1', 'worker', 'routing', 'all'];
  if (!valid.includes(command)) {
    console.error(`[ERROR] Unknown command "${command}". Use: ${valid.join(', ')}`);
    process.exit(1);
  }

  console.log(`[setup] Account ${ACCOUNT_ID}`);
  if (command === 'd1') {
    await ensureD1();
  } else if (command === 'worker') {
    const databaseId = await ensureD1();
    await deployWorker(databaseId);
  } else if (command === 'routing') {
    await enforceRouting();
  } else {
    const databaseId = await ensureD1();
    await deployWorker(databaseId);
    await enforceRouting();
  }
  console.log('[setup] Complete.');
}

main().catch((error) => {
  console.error(`[ERROR] ${error.message}`);
  process.exit(1);
});
