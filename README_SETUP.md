# Setup Guide: Cloudflare Email Panel

Panduan setup Cloudflare dan konfigurasi dasar panel.

## Prasyarat

- Node.js 18+
- Akun Cloudflare dengan Email Routing aktif
- Telegram bot untuk login (opsional tapi disarankan)

## Cara otomatis (rekomendasi)

Gunakan script AIO:
```bash
npm run setup
```

Script akan:
- Install dependencies
- Membuat `.env`
- Login ke Wrangler
- Membuat database D1
- Deploy worker

## Konfigurasi manual

### 1) Environment variables

Buat `.env` di root:
```env
PORT=3000
CF_API_TOKEN=token_api
CF_ACCOUNT_ID=account_id
CF_ZONE_ID=zone_id
CF_D1_DATABASE_ID=d1_database_id
TELEGRAM_BOT_TOKEN=telegram_bot_token
TELEGRAM_MASTER_ID=telegram_user_id
```

### 2) API Token Cloudflare

Buat token dengan izin berikut:
- Zone > Email Routing Rules: Edit
- Zone > Email Routing Addresses: Edit
- Zone > Zone: Read
- Account > D1: Edit

### 3) Setup Worker + D1

```bash
cd worker
npm install
npx wrangler login
npx wrangler d1 create email-db
```

Salin `database_id` ke `.env` dan buat `worker/wrangler.toml` dari contoh:
```bash
copy wrangler.toml.example wrangler.toml
```
Lalu isi `database_id` dan deploy:
```bash
npx wrangler deploy
```
Catatan: `worker/wrangler.toml` di-ignore agar tidak kepublish.

## Konfigurasi Cloudflare

1) Enable Email Routing di dashboard Cloudflare.
2) Buat rule "Send to Worker" ke worker yang sudah dideploy (misal `inbox-worker`).

## Setup bot login (opsional)

Isi `TELEGRAM_BOT_TOKEN` dan `TELEGRAM_MASTER_ID` di `.env`, lalu jalankan:
```bash
npm run start:bot
```

Login di panel butuh approval:
- Klik "Request Register (10m)" di UI
- Approve lewat `/register` di bot

## Docker

Untuk VPS gunakan Docker:
```bash
echo "{\"pending\":null}" > .register-request.json
docker compose up -d
```

Catatan:
- Gunakan HTTPS di VPS agar secure cookie aktif.
