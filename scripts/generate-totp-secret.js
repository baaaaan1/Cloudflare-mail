#!/usr/bin/env node
/**
 * Generate a TOTP secret for 2FA login.
 *
 * Usage:
 *   node scripts/generate-totp-secret.js
 *
 * Scan the QR with your authenticator app (Google Authenticator, Aegis,
 * Authy, ...), then add the printed TOTP_SECRET to your environment
 * (.env locally, or the Dokploy "Environment" tab) so it survives
 * restarts and redeploys.
 */

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const ISSUER = 'Cloudflare Email Panel';

async function main() {
  const secret = speakeasy.generateSecret({ length: 20 });
  const otpauthUrl = `otpauth://totp/${encodeURIComponent(`${ISSUER}:admin`)}?secret=${secret.base32}&issuer=${encodeURIComponent(ISSUER)}`;

  console.log('\n1. Add this account to your authenticator app:');
  try {
    const qr = await QRCode.toString(otpauthUrl, { type: 'terminal', margin: 1 });
    console.log(qr);
  } catch {
    // terminal QR unsupported — the otpauth URL below still works
  }
  console.log(`   ${otpauthUrl}`);
  console.log('\n2. Then set this in your environment to persist it:');
  console.log(`\n   TOTP_SECRET=${secret.base32}\n`);
}

main().catch((e) => { console.error(e); process.exit(1); });
