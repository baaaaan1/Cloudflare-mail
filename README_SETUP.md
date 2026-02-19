# Setup Guide: Cloudflare Email Panel

Panduan setup Cloudflare dan konfigurasi dasar panel.

## Prasyarat

- Node.js 18+
- Akun Cloudflare dengan Email Routing aktif
- Telegram bot untuk login (opsional tapi disarankan)
- VPS: Docker + Docker Compose (untuk deploy via Docker)
- Git (jika clone dari GitHub)

### Install Docker (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

Log out dan login lagi agar grup docker aktif, lalu cek:
```bash
docker --version
docker compose version
```

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
Optional (local dev only):
```env
ALLOW_UNAUTHENTICATED=true
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
- Jika ingin login password: `/password` (auto-generate) atau `/password 16` atau `/password your_password`

## Docker

Untuk VPS gunakan Docker:
```bash
echo "{\"pending\":null}" > .register-request.json
docker compose up -d
```

Catatan:
- Gunakan HTTPS di VPS agar secure cookie aktif.
