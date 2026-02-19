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

## Docker

```bash
docker compose up -d
```

## Troubleshooting

- Unauthorized: token expired, request register lagi dan login ulang.
- Inbox kosong: pastikan Worker sudah deploy dan rule "Send to Worker" sudah dibuat.
