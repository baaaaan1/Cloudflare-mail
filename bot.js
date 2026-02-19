const { Telegraf } = require('telegraf');
require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const token = process.env.TELEGRAM_BOT_TOKEN;
const masterId = process.env.TELEGRAM_MASTER_ID;
const OTP_LABEL = 'Cloudflare Email Panel';
const REGISTER_REQUEST_FILE = path.join(__dirname, '.register-request.json');
const DEFAULT_REGISTER_MS = 5 * 60 * 1000;
const PASSWORD_DELETE_MS = 60 * 1000;

if (!token || !masterId) {
  console.error('Missing TELEGRAM_BOT_TOKEN or TELEGRAM_MASTER_ID in .env file');
  process.exit(1);
}

const bot = new Telegraf(token);

function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

function generatePassword(length = 16) {
  const size = Math.max(8, Math.min(64, length));
  const raw = crypto.randomBytes(Math.ceil(size * 0.75)).toString('base64');
  return raw.replace(/[+/=]/g, '').slice(0, size);
}

function setPasswordInEnv(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  updateEnvFile('PASSWORD_SALT', salt);
  updateEnvFile('PASSWORD_HASH', hash);
  return { salt, hash };
}

async function sendEphemeral(ctx, text, ttlMs = PASSWORD_DELETE_MS) {
  try {
    const msg = await ctx.reply(text);
    setTimeout(() => {
      ctx.telegram.deleteMessage(ctx.chat.id, msg.message_id).catch(() => {});
    }, ttlMs);
  } catch {}
}

function updateEnvFile(key, value) {
  const envPath = path.join(__dirname, '.env');
  let content = '';
  if (fs.existsSync(envPath)) {
    content = fs.readFileSync(envPath, 'utf8');
  }

  const regex = new RegExp(`^${key}=.*`, 'm');
  if (regex.test(content)) {
    content = content.replace(regex, `${key}=${value}`);
  } else {
    content += `\n${key}=${value}`;
  }

  fs.writeFileSync(envPath, content.trim() + '\n');
}

function getEnvValue(key) {
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
  return process.env[key] || null;
}

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

function clearPendingRegisterRequest() {
  const store = readRegisterStore();
  if (store.pending) {
    store.pending = null;
    writeRegisterStore(store);
  }
}

function parseDurationArg(text) {
  const parts = String(text || '').trim().split(/\s+/).slice(1);
  if (!parts.length) return DEFAULT_REGISTER_MS;
  const match = parts[0].match(/^(\d+)([mjh])$/i);
  if (!match) return null;
  const value = parseInt(match[1], 10);
  if (!Number.isFinite(value) || value <= 0) return null;
  const unit = match[2].toLowerCase();
  if (unit === 'm') return value * 60 * 1000;
  return value * 60 * 60 * 1000;
}

function formatDuration(ms) {
  const minutes = Math.round(ms / 60000);
  if (minutes >= 60 && minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

function buildOtpAuthUrl(secretBase32) {
  return speakeasy.otpauthURL({
    secret: secretBase32,
    label: OTP_LABEL,
    issuer: OTP_LABEL,
    encoding: 'base32',
  });
}

function sendTfaSetup(ctx, otpAuthUrl, secretBase32) {
  QRCode.toDataURL(otpAuthUrl, (err, data_url) => {
    if (err) {
      ctx.reply('Error generating QR code');
      return;
    }
    const qrCode = Buffer.from(data_url.split(',')[1], 'base64');
    ctx.replyWithPhoto({ source: qrCode }, {
      caption: 'Scan this QR code with your 2FA app.',
    });
  });
  ctx.reply(`2FA secret (manual): ${secretBase32}`);
}

bot.start((ctx) => {
  ctx.reply('Welcome to the registration bot!');
});

bot.command('register', (ctx) => {
  if (ctx.from.id.toString() === masterId) {
    const durationMs = parseDurationArg(ctx.message?.text);
    if (!durationMs) {
      ctx.reply('Invalid duration. Use /register 5m or /register 12j (hours).');
      return;
    }

    const pending = getPendingRegisterRequest();
    if (pending) {
      clearPendingRegisterRequest();
      ctx.reply('Pending register request approved.');
    }

    const expiresAt = Date.now() + durationMs;
    const accessToken = generateToken();
    const secret = speakeasy.generateSecret({ name: OTP_LABEL });

    updateEnvFile('ACCESS_TOKEN', accessToken);
    updateEnvFile('ACCESS_TOKEN_TIMESTAMP', Date.now());
    updateEnvFile('ACCESS_TOKEN_EXPIRES_AT', expiresAt);
    updateEnvFile('TFA_SECRET', secret.base32);
    updateEnvFile('TFA_SECRET_EXPIRES_AT', expiresAt);

    sendTfaSetup(ctx, secret.otpauth_url || buildOtpAuthUrl(secret.base32), secret.base32);
    ctx.reply(`Access key: ${accessToken}`);
    ctx.reply(`Expires in: ${formatDuration(durationMs)}`);
  } else {
    ctx.reply('You are not authorized to perform this action.');
  }
});

bot.command('password', (ctx) => {
  if (ctx.from.id.toString() !== masterId) {
    ctx.reply('You are not authorized to perform this action.');
    return;
  }
  const parts = String(ctx.message?.text || '').trim().split(/\s+/).slice(1);
  let password = '';
  let generated = false;
  if (parts.length) {
    const arg = parts.join(' ');
    if (/^\d+$/.test(arg)) {
      password = generatePassword(parseInt(arg, 10));
      generated = true;
    } else {
      password = arg;
    }
  } else {
    password = generatePassword();
    generated = true;
  }

  if (!password || password.length < 8) {
    ctx.reply('Password too short. Use /password 12 or /password your_password');
    return;
  }

  setPasswordInEnv(password);
  if (generated) {
    sendEphemeral(ctx, `Password generated (auto-delete in 60s). Save it now:\n${password}`);
  } else {
    ctx.reply('Password updated. (Not echoed back for safety.)');
  }
});

bot.launch();

console.log('Telegram bot started...');
