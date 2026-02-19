# Running the Cloudflare Email Panel

Panduan singkat untuk menjalankan server dan bot, lalu menggunakan panel.

## Menjalankan server

```bash
npm start
```

Untuk development:
```bash
npm run dev
```

Buka `http://localhost:3000`.

## Menjalankan bot (Telegram)

```bash
npm run start:bot
```

Jalankan server dan bot sekaligus:
```bash
npm run start:all
```

## Login dan registrasi

1) Di panel, klik "Request Register (10m)".
2) Approve lewat bot:
   - `/register` default 5 menit
   - `/register 5m` atau `/register 12h`
3) Bot akan kirim Access Key dan 2FA secret + QR.
4) Login pakai Access Key atau 2FA Code.
5) (Opsional) Set password via bot: `/password` atau `/password 16` atau `/password your_password`, lalu login via tab Password.

## Menggunakan panel

- Addresses: pilih alamat untuk filter inbox.
- Add Rule: buat routing baru (Forward Drop Worker).
- Inbox: klik email untuk membuka viewer HTML atau Text.
- Theme: ganti preset atau custom color di sidebar.

## Inisialisasi database inbox

Jika tabel belum ada, jalankan init lewat API (butuh auth):
```bash
curl -X POST http://localhost:3000/api/inbox/init -H "Authorization: Bearer YOUR_ACCESS_KEY"
```
Catatan: Header ini hanya berlaku jika Access Key diaktifkan. Jika pakai password/2FA, login via browser dan gunakan session cookie.

## Docker

```bash
echo "{\"pending\":null}" > .register-request.json
docker compose up -d
```

## VPS deploy script (Docker)

```bash
./scripts/deploy_vps.sh
```

Deploy worker via Wrangler (optional):
```bash
./scripts/deploy_vps.sh --deploy-worker
```

## Troubleshooting

- Unauthorized: token expired, request register lagi dan login ulang.
- Inbox kosong: pastikan Worker sudah deploy dan rule "Send to Worker" sudah dibuat.
