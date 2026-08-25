#!/usr/bin/env node
/**
 * Generate PASSWORD_SALT + PASSWORD_HASH (scrypt) for the panel .env.
 *
 * Usage:
 *   node scripts/generate-password.js                     # interactive prompt
 *   node scripts/generate-password.js --password "secret" # pass directly
 */

const crypto = require('crypto');

const SALT_BYTES = 16;
const HASH_BYTES = 64;
const SCRYPT_KEYLEN = HASH_BYTES;

function acceptsArgvPassword() {
  const idx = process.argv.indexOf('--password');
  if (idx !== -1 && process.argv[idx + 1]) {
    return process.argv[idx + 1];
  }
  return null;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), String(salt), SCRYPT_KEYLEN).toString('hex');
}

function printResult(salt, hash) {
  console.log('\nAdd these to your .env:\n');
  console.log(`PASSWORD_SALT=${salt}`);
  console.log(`PASSWORD_HASH=${hash}`);
  console.log('\nPASSWORD_HASH is the hex-encoded scrypt hash of your password (salt as hexadecimal).');
}

function main() {
  const fromArgv = acceptsArgvPassword();
  if (fromArgv !== null) {
    if (fromArgv.length < 8) {
      console.error('Password must be at least 8 characters.');
      process.exit(1);
    }
    const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
    printResult(salt, hashPassword(fromArgv, salt));
    return;
  }

  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  readline.question('Password (min 8 characters): ', (password) => {
    readline.question('Confirm password: ', (confirm) => {
      readline.close();
      const pass = String(password || '');
      if (pass !== String(confirm || '')) {
        console.error('Passwords do not match.');
        process.exit(1);
      }
      if (pass.length < 8) {
        console.error('Password must be at least 8 characters.');
        process.exit(1);
      }
      const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
      printResult(salt, hashPassword(pass, salt));
    });
  });
}

main();
