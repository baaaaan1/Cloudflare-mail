# Cloudflare Email Panel

![license](https://img.shields.io/badge/license-ISC-blue.svg)
![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)
![express](https://img.shields.io/badge/express-4.x-informational.svg)
![status](https://img.shields.io/badge/state-stable-success.svg)

Self hosted web panel to manage Cloudflare Email Routing rules, destinations, and inbox messages stored in D1. Built with Node.js and vanilla JS CSS.

## Features

- Address list + inbox filtering per address
- Rule management (create edit delete toggle)
- Access key, 2FA, or password login (approved via Telegram bot)
- Multi domain support with domain dropdown
- Glass UI with theme presets and custom accent
- Docker ready

## Quick start (local)

1) Copy env example
```bash
cp .env.example .env
```

2) Fill required values in `.env`
```env
PORT=3000
CF_API_TOKEN=your_api_token
CF_ACCOUNT_ID=your_account_id
CF_ZONE_ID=your_zone_id
CF_D1_DATABASE_ID=your_d1_database_id
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_MASTER_ID=your_telegram_id
```
Optional (local dev only):
```env
ALLOW_UNAUTHENTICATED=true
```
Note: auth is required by default. Without any auth configured, the API returns 401 unless `ALLOW_UNAUTHENTICATED=true`.

Optional password login (adds third login option):
```bash
node -e "const crypto=require('crypto');const pwd=process.argv[1];if(!pwd){console.error('Usage: node -e \"...\" your_password');process.exit(1);}const salt=crypto.randomBytes(16).toString('hex');const hash=crypto.scryptSync(pwd,salt,64).toString('hex');console.log('PASSWORD_SALT='+salt);console.log('PASSWORD_HASH='+hash);" your_password
```
Add both values to `.env`.

3) Install and run
```bash
npm install
npm start
```

4) Open `http://localhost:3000`

## Bot and login flow

- Run bot: `npm run start:bot` or `npm run start:all`
- In panel, click "Request Register (10m)"
- Approve in Telegram bot:
  - `/register` default 5 minutes
  - `/register 5m` or `/register 12h`
- Bot sends access key and 2FA secret plus QR
- Set panel password: `/password` (auto-generate, auto-delete) or `/password 16` or `/password your_password`

## Docker (VPS)

1) Create `.env` and `.register-request.json`
```bash
echo "{\"pending\":null}" > .register-request.json
```

2) Build and run
```bash
docker compose up -d
```

Alternative (script):
```bash
./scripts/deploy_vps.sh
```

3) Open `http://your-vps-ip:3000`

Notes:
- Use HTTPS on VPS so secure cookies work (NODE_ENV=production).
- Keep panel behind VPN or Cloudflare Access.

## Security notes

- Do not commit `.env` or `.register-request.json`.
- Protect the panel with network access control or reverse proxy auth.
- Use HTTPS in production.

## Project structure

- `server.js` Express API server
- `public/` frontend app
- `bot.js` Telegram bot for access key and 2FA
- `worker/` Cloudflare Worker for inbox storage
- `worker/wrangler.toml.example` template (copy to `worker/wrangler.toml`)

## License

ISC
