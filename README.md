# Cloudflare Email Panel

Panel self-hosted untuk mengelola Cloudflare Email Routing, destination, rules, dan inbox yang disimpan di Cloudflare D1. Production memakai Docker, Caddy, dan HTTPS otomatis.

## Production URL

Default domain: **https://mail.ayaneo.my.id**.

Port aplikasi `3000` tidak dibuka ke internet. Caddy membuka port `80` dan `443`, lalu meneruskan request HTTPS ke container panel internal.

## Prasyarat VPS

- Ubuntu atau Debian VPS
- DNS record **A** `mail.ayaneo.my.id` mengarah ke IPv4 VPS
- Firewall/security group VPS mengizinkan TCP `80` dan `443`
- Cloudflare **SSL/TLS encryption mode: Full (strict)**

DNS boleh diproxy (orange cloud). Bila sertifikat tidak terbit, pastikan origin VPS dapat diakses pada port 80/443 dan tidak digunakan web server lain.

## Instalasi AIO

Clone repo ke VPS, masuk ke folder repo, lalu jalankan:

```bash
sudo bash scripts/install_vps.sh
```

Installer memasang Docker Engine + Compose bila belum tersedia, membuat `.env` tanpa menimpa file lama, meminta domain (default `mail.ayaneo.my.id`), membuka editor `.env`, lalu build dan menjalankan container.

Isi minimal `.env`:

```env
PORT=3000
CADDY_DOMAIN=mail.ayaneo.my.id
CLOUDFLARE_API_TOKEN=your_api_token
CLOUDFLARE_ACCOUNT_ID=your_account_id
CLOUDFLARE_ZONE_ID=your_zone_id
CLOUDFLARE_D1_DATABASE_ID=your_d1_database_id
PASSWORD_HASH=
PASSWORD_SALT=
```

Untuk password awal, kosongkan `PASSWORD_HASH` dan `PASSWORD_SALT`, buka panel, lalu buat password melalui layar setup. `.env` dibind ke container sehingga konfigurasi dari panel tersimpan di VPS.

## Operasi harian

Jalankan dari root project di VPS:

```bash
# Status container
docker compose ps

# Log live panel dan Caddy
docker compose logs -f

# Update aplikasi
git pull --rebase
docker compose up -d --build --remove-orphans

# Restart setelah edit .env manual
docker compose restart panel

# Stop stack (sertifikat Caddy tetap tersimpan di Docker volume)
docker compose down
```

`/healthz` adalah endpoint liveness container. `/health` juga memeriksa akses Cloudflare API.

## Worker dan D1 (opsional untuk Inbox)

1. Buat database D1 dan isi `CLOUDFLARE_D1_DATABASE_ID` di root `.env`.
2. Buat konfigurasi lokal Worker:

   ```bash
   cp worker/wrangler.toml.example worker/wrangler.toml
   ```

3. Isi `database_id` pada `worker/wrangler.toml` dengan ID D1.
4. Deploy Worker dari mesin yang punya Wrangler login, atau dari VPS:

   ```bash
   bash scripts/deploy_vps.sh --deploy-worker
   ```

5. Pada Cloudflare Email Routing, buat rule **Send to Worker** menuju `inbox-worker`.

Token API memerlukan izin yang sesuai untuk Email Routing, Zone read, Workers, dan D1 (bila inbox digunakan).

## Local development

```bash
cp .env.example .env
npm ci
npm run dev
```

Buka `http://localhost:3000`. HTTPS dan cookie `Secure` aktif saat `NODE_ENV=production` di Docker/VPS.

## Struktur utama

- `server.js` — Express API dan static frontend
- `public/` — frontend vanilla JavaScript
- `worker/` — Cloudflare Email Worker dan D1 schema
- `docker-compose.yml` — panel + Caddy production stack
- `Caddyfile` — reverse proxy dan HTTPS otomatis
- `scripts/install_vps.sh` — AIO installer Ubuntu/Debian
- `scripts/deploy_vps.sh` — redeploy stack / optional Worker deploy

## Keamanan

- Jangan commit `.env` atau `worker/wrangler.toml`.
- Gunakan token Cloudflare dengan scope minimum dan rotasi token bila bocor.
- Aktifkan password panel sebelum digunakan.
- Untuk pembatasan ekstra, lindungi hostname dengan Cloudflare Access atau firewall/IP allowlist.

## License

ISC
